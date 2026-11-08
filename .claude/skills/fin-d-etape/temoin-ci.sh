#!/bin/sh
# temoin-ci.sh ETAPE PROGRAMME[:ARGUMENT]... : lance des programmes de test
# de l'étape (ETAPE/linux/construits/PROGRAMME) sous le noyau exact de la CI,
# dans QEMU, comme `make tests-hote` les lance sur la machine de GitHub.
#
#   sh .claude/skills/fin-d-etape/temoin-ci.sh 06i-claude-p copies:/dev/shm surveillance:/dev/shm tcp unix
#
# Pourquoi : les tests sur l'hôte suivent le noyau de la machine, et celui de
# la CI n'est pas le nôtre (Linux 7.0 en novembre 2026, 6.18 sous WSL) ; et
# la CI s'arrête au premier échec, un push par écart. Le noyau vient du paquet
# d'Ubuntu (NOYAU, celui que disent les notes de l'image de GitHub, releases
# de actions/runner-images, « Kernel Version ») ; un /init statique monte
# /proc, /sys, /dev, /dev/shm (un tmpfs) et /tmp, active lo, puis lance
# chaque programme en utilisateur 1000 dans /dev/shm, comme la CI (un
# utilisateur ordinaire, la sortie sur la console) ; la machine s'éteint à
# la fin. Les programmes doivent être construits (make dans l'étape), et
# statiques. Ce que la CI fait de plus (le dépôt sur un disque, sudo pour
# tests-hote-root, l'héritage des descripteurs) n'est pas imité : voir les
# pièges de 6h dans SKILL.md.
set -eu
NOYAU=${NOYAU:-7.0.0-1017-azure}
etape=${1:?usage : temoin-ci.sh ETAPE PROGRAMME[:ARGUMENT]...}
shift
depot=$(git rev-parse --show-toplevel)
travail=/tmp/claude-1000/temoin-ci
mkdir -p "$travail/paquet" "$travail/noyau"

# Le noyau, une fois.
if [ ! -f "$travail/noyau/vmlinuz-$NOYAU" ]; then
    (cd "$travail/paquet" && apt-get download "linux-image-unsigned-$NOYAU")
    dpkg-deb -x "$travail/paquet/linux-image-unsigned-${NOYAU}"_*.deb "$travail/paquet/ext"
    cp "$travail/paquet/ext/boot/vmlinuz-$NOYAU" "$travail/noyau/"
fi

# Le /init : la liste des programmes, lue dans /liste (une ligne par
# programme : son chemin, puis son argument éventuel).
cat > "$travail/init.c" <<'FIN'
#include <fcntl.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void)
{
    mount("proc", "/proc", "proc", 0, 0);
    mount("sysfs", "/sys", "sysfs", 0, 0);
    mount("devtmpfs", "/dev", "devtmpfs", 0, 0);
    int c = open("/dev/console", O_RDWR);
    if (c >= 0) {
        dup2(c, 0);
        dup2(c, 1);
        dup2(c, 2);
    }
    mkdir("/dev/shm", 01777);
    mount("tmpfs", "/dev/shm", "tmpfs", 0, "mode=1777");
    mount("tmpfs", "/tmp", "tmpfs", 0, "mode=1777");
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq r;
    memset(&r, 0, sizeof r);
    strcpy(r.ifr_name, "lo");
    ioctl(s, SIOCGIFFLAGS, &r);
    r.ifr_flags |= IFF_UP;
    ioctl(s, SIOCSIFFLAGS, &r);
    close(s);
    struct utsname u;
    uname(&u);
    printf("[temoin] %s %s\n", u.sysname, u.release);
    FILE *liste = fopen("/liste", "r");
    char prog[256], arg[256];
    while (liste && fscanf(liste, "%255s %255s", prog, arg) == 2) {
        fflush(stdout);
        pid_t p = fork();
        if (p == 0) {
            if (chdir("/dev/shm") || setgid(1000) || setuid(1000))
                _exit(126);
            execl(prog, prog, strcmp(arg, "-") ? arg : (char *)0, (char *)0);
            _exit(127);
        }
        int st = 0;
        waitpid(p, &st, 0);
        printf("[temoin] %s : fin %d\n", prog, st);
    }
    fflush(stdout);
    sync();
    reboot(RB_POWER_OFF);
    return 0;
}
FIN
gcc -static -O2 -Wall -o "$travail/init" "$travail/init.c"

# L'archive : la description d'archive.sh (celle de nos étapes).
: > "$travail/liste"
{
    printf 'dir /proc 755 0 0\ndir /sys 755 0 0\ndir /dev 755 0 0\ndir /tmp 1777 0 0\ndir /t 755 0 0\n'
    printf 'file /init %s/init 755 0 0\nfile /liste %s/liste 644 0 0\n' "$travail" "$travail"
    for p in "$@"; do
        nom=${p%%:*}
        arg=-
        [ "$nom" = "$p" ] || arg=${p#*:}
        printf '/t/%s %s\n' "$nom" "$arg" >> "$travail/liste"
        printf 'file /t/%s %s/%s/linux/construits/%s 755 0 0\n' "$nom" "$depot" "$etape" "$nom"
    done
} > "$travail/archive.txt"
(cd "$depot/$etape" && sh archive.sh "$travail/temoin.cpio" "$travail/archive.txt")

timeout 900 qemu-system-x86_64 -kernel "$travail/noyau/vmlinuz-$NOYAU" -initrd "$travail/temoin.cpio" \
    -append "console=ttyS0 panic=-1 quiet" -m 1G -cpu max -display none -no-reboot -serial stdio \
    | tee "$travail/serie.log" | grep -a -E '^\[temoin\]|: ECHEC|toutes les verifications'
