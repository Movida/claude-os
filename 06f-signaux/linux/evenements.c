/*
 * eventfd et epoll (6d) : la boucle d'événements de Bun, créée mais pas
 * encore attendue (epoll_wait vient en 6f). Il tourne dans notre noyau et
 * sur l'hôte (make tests-hote) : chaque ligne doit dire « ok » des deux
 * côtés, d'après ce qu'a mesuré la sonde sur Linux 6.18. Rien n'y attend :
 * les eventfd lus vides sont non bloquants.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>

static int echecs;

static void verifier(int ok, const char *quoi)
{
    printf("[linux] evenements : %s : %s\n", quoi, ok ? "ok" : "ECHEC");
    echecs += !ok;
}

/* Le numéro d'erreur d'un appel (0 s'il a réussi). */
static int erreur(long r)
{
    return r < 0 ? errno : 0;
}

static void compteurs(void)
{
    uint64_t v;
    int e = eventfd(3, 0);
    verifier(e >= 0 && read(e, &v, 8) == 8 && v == 3, "eventfd(3) : read rend 3");
    verifier(erreur(read(e, &v, 4)) == EINVAL, "read de 4 octets : EINVAL");
    v = 0xffffffffffffffffULL;
    verifier(erreur(write(e, &v, 8)) == EINVAL, "write de 0xffffffffffffffff : EINVAL");
    v = 5;
    verifier(write(e, &v, 8) == 8 && write(e, &v, 8) == 8 && read(e, &v, 8) == 8 && v == 10,
             "deux write de 5, un read de 10 (le compteur s'ajoute, puis se vide)");
    verifier(erreur(syscall(SYS_write, e, (void *)8, 8)) == EFAULT, "write d'une adresse invalide : EFAULT");
    close(e);

    int n = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    verifier(erreur(read(n, &v, 8)) == EAGAIN, "non bloquant et vide : EAGAIN");
    v = 0xfffffffffffffffeULL;
    verifier(write(n, &v, 8) == 8, "jusqu'a 0xfffffffffffffffe : accepte");
    v = 1;
    verifier(erreur(write(n, &v, 8)) == EAGAIN, "un de plus deborderait : EAGAIN");
    verifier(fcntl(n, F_GETFL) == (O_RDWR | O_NONBLOCK), "F_GETFL : O_RDWR | O_NONBLOCK");
    verifier(fcntl(n, F_GETFD) == FD_CLOEXEC, "EFD_CLOEXEC : FD_CLOEXEC");
    close(n);

    int s = eventfd(2, EFD_SEMAPHORE | EFD_NONBLOCK);
    verifier(read(s, &v, 8) == 8 && v == 1 && read(s, &v, 8) == 8 && v == 1 && erreur(read(s, &v, 8)) == EAGAIN,
             "EFD_SEMAPHORE : 1, puis 1, puis vide");
    close(s);
    verifier(erreur(eventfd(0, 0x10)) == EINVAL, "un drapeau inconnu : EINVAL");
    verifier(fcntl(e = eventfd(0, 0), F_GETFL) == O_RDWR, "F_GETFL d'un eventfd bloquant : O_RDWR");
    close(e);
}

static void fichier_anonyme(void)
{
    int e = eventfd(0, 0), p = epoll_create1(0);
    struct stat se, sp, sf;
    fstat(e, &se);
    fstat(p, &sp);
    stat("/", &sf);
    verifier((se.st_mode & 07777) == 0600 && (se.st_mode & S_IFMT) == 0 && se.st_uid == 0 && se.st_size == 0
             && se.st_nlink == 1, "fstat d'un eventfd : 0600 sans type, a root, vide, un lien");
    verifier(se.st_ino == sp.st_ino && se.st_dev == sp.st_dev && se.st_dev != sf.st_dev,
             "eventfd et epoll : le meme inode anonyme, un autre systeme que la racine");
    uint64_t v;
    verifier(lseek(e, 10, SEEK_SET) == 0 && lseek(p, 0, SEEK_END) == 0, "lseek : 0 (pas de position)");
    verifier(erreur(pread(e, &v, 8, 0)) == ESPIPE && erreur(pwrite(e, &v, 8, 0)) == ESPIPE, "pread, pwrite : ESPIPE");
    verifier(mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, e, 0) == MAP_FAILED && errno == ENODEV, "mmap : ENODEV");
    int n;
    verifier(erreur(ioctl(e, FIONREAD, &n)) == ENOTTY, "FIONREAD : ENOTTY");
    verifier(erreur(read(p, &v, 8)) == EINVAL && erreur(write(p, &v, 8)) == EINVAL, "un epoll ne se lit ni ne s'ecrit : EINVAL");
    verifier(fcntl(p, F_GETFL) == O_RDWR, "F_GETFL d'un epoll : O_RDWR");
    verifier(erreur(fchdir(e)) == ENOTDIR, "fchdir vers un eventfd : ENOTDIR");
    verifier(erreur(ioctl(p, FIONREAD, &n)) == EINVAL, "FIONREAD d'un epoll : EINVAL (il repond lui-meme)");
    verifier(erreur(fsync(e)) == EINVAL && erreur(fdatasync(p)) == EINVAL && syncfs(e) == 0,
             "fsync, fdatasync : EINVAL (pas d'operation fsync) ; syncfs : 0");
    /* Ses attributs ne changent pas : EOPNOTSUPP (anon_inode_setattr),
     * sauf les dates à maintenant, refusées avant par les droits. */
    struct timespec dates[2] = { { 1, 0 }, { 1, 0 } };
    verifier(erreur(fchmod(e, 0644)) == EOPNOTSUPP && erreur(fchown(e, -1, -1)) == EOPNOTSUPP
             && erreur(futimens(e, dates)) == EOPNOTSUPP && erreur(futimens(e, NULL)) == EACCES,
             "fchmod, fchown, futimens : EOPNOTSUPP ; futimens a maintenant : EACCES");
    /* readv lit un eventfd d'un coup, sur tous les morceaux ; writev,
     * morceau par morceau. */
    uint64_t un = 5, lu = 0;
    struct iovec deux[2] = { { &lu, 4 }, { (char *)&lu + 4, 4 } };
    struct iovec deux_w[2] = { { &un, 4 }, { (char *)&un + 4, 4 } };
    verifier(write(e, &un, 8) == 8 && readv(e, deux, 2) == 8 && lu == 5, "readv de 4 + 4 octets : 8, le compteur");
    verifier(erreur(writev(e, deux_w, 2)) == EINVAL, "writev de 4 + 4 octets : EINVAL");
    close(e);
    close(p);
}

static void surveillance(void)
{
    int p = epoll_create1(EPOLL_CLOEXEC), e = eventfd(0, 0), e2 = eventfd(0, 0);
    struct epoll_event ev = { .events = EPOLLIN, .data.u64 = 7 };
    verifier(p >= 0 && fcntl(p, F_GETFD) == FD_CLOEXEC, "epoll_create1(EPOLL_CLOEXEC)");
    verifier(erreur(epoll_create1(1)) == EINVAL && erreur(epoll_create(0)) == EINVAL,
             "epoll_create1(1), epoll_create(0) : EINVAL");
    verifier(epoll_ctl(p, EPOLL_CTL_ADD, e, &ev) == 0, "ADD d'un eventfd");
    verifier(erreur(epoll_ctl(p, EPOLL_CTL_ADD, e, &ev)) == EEXIST, "ADD deux fois : EEXIST");
    ev.events = EPOLLIN | EPOLLET;
    verifier(epoll_ctl(p, EPOLL_CTL_MOD, e, &ev) == 0, "MOD (EPOLLET, comme Bun)");
    verifier(erreur(epoll_ctl(p, EPOLL_CTL_MOD, e2, &ev)) == ENOENT, "MOD d'un absent : ENOENT");
    verifier(erreur(epoll_ctl(p, EPOLL_CTL_DEL, e2, NULL)) == ENOENT, "DEL d'un absent : ENOENT");
    verifier(erreur(epoll_ctl(p, EPOLL_CTL_ADD, p, &ev)) == EINVAL, "ADD de l'epoll lui-meme : EINVAL");
    verifier(erreur(epoll_ctl(p, 9, e, &ev)) == EINVAL, "une operation inconnue : EINVAL");
    verifier(erreur(epoll_ctl(e, EPOLL_CTL_ADD, e2, &ev)) == EINVAL, "un premier descripteur qui n'est pas un epoll : EINVAL");
    verifier(erreur(epoll_ctl(p, EPOLL_CTL_ADD, 999, &ev)) == EBADF, "un descripteur ferme : EBADF");
    verifier(erreur(epoll_ctl(p, EPOLL_CTL_ADD, 999, NULL)) == EFAULT, "un evenement nul : EFAULT, avant EBADF");
    verifier(epoll_ctl(p, EPOLL_CTL_DEL, e, NULL) == 0, "DEL avec un evenement nul : 0");
    /* Ce qui ne sait pas dire « pret » : EPERM. */
    int f = open("/etc/hosts", O_RDONLY), d = open("/", O_RDONLY | O_DIRECTORY);
    int nul = open("/dev/null", O_RDONLY), zero = open("/dev/zero", O_RDONLY), u = open("/dev/urandom", O_RDONLY);
    int r = open("/dev/random", O_RDONLY);
    if (f < 0)
        f = open("/etc/bonjour.txt", O_RDONLY);
    verifier(erreur(epoll_ctl(p, EPOLL_CTL_ADD, f, &ev)) == EPERM && erreur(epoll_ctl(p, EPOLL_CTL_ADD, d, &ev)) == EPERM,
             "un fichier ordinaire, un dossier : EPERM");
    verifier(erreur(epoll_ctl(p, EPOLL_CTL_ADD, nul, &ev)) == EPERM && erreur(epoll_ctl(p, EPOLL_CTL_ADD, zero, &ev)) == EPERM
             && erreur(epoll_ctl(p, EPOLL_CTL_ADD, u, &ev)) == EPERM, "/dev/null, /dev/zero, /dev/urandom : EPERM");
    verifier(epoll_ctl(p, EPOLL_CTL_ADD, r, &ev) == 0, "/dev/random : accepte");
    int o = open("/", O_PATH);
    verifier(erreur(epoll_ctl(p, EPOLL_CTL_ADD, o, &ev)) == EBADF, "un descripteur O_PATH : EBADF");
    /* EPOLLEXCLUSIVE. */
    struct epoll_event ex = { .events = EPOLLIN | EPOLLEXCLUSIVE };
    verifier(epoll_ctl(p, EPOLL_CTL_ADD, e2, &ex) == 0, "ADD avec EPOLLEXCLUSIVE");
    verifier(erreur(epoll_ctl(p, EPOLL_CTL_MOD, e2, &ev)) == EINVAL, "MOD d'une inscription EPOLLEXCLUSIVE : EINVAL");
    verifier(erreur(epoll_ctl(p, EPOLL_CTL_MOD, e, &ex)) == EINVAL, "MOD avec EPOLLEXCLUSIVE : EINVAL");
    /* Un epoll dans un epoll, et une boucle. */
    int q = epoll_create1(0);
    verifier(epoll_ctl(q, EPOLL_CTL_ADD, p, &ev) == 0, "un epoll dans un epoll : accepte");
    verifier(erreur(epoll_ctl(p, EPOLL_CTL_ADD, q, &ev)) == ELOOP, "une boucle : ELOOP");
    /* Pas plus de quatre étages d'epoll (EP_MAX_NESTS) : une chaîne de
     * cinq emboîtements, le cinquième est refusé. */
    int chaine[6], refus = -1;
    for (int i = 0; i < 6; i++)
        chaine[i] = epoll_create1(0);
    for (int i = 1; i < 6 && refus < 0; i++)
        if (epoll_ctl(chaine[i], EPOLL_CTL_ADD, chaine[i - 1], &ev) < 0)
            refus = errno == ELOOP ? i : 99;
    verifier(refus == 5, "cinq epoll emboites : le cinquieme, ELOOP");
    for (int i = 0; i < 6; i++)
        close(chaine[i]);
    /* L'inscription est (fichier, numero) : un dup garde l'inscription au
     * nom du premier numero, meme ferme ; le dup peut s'inscrire a son tour. */
    int e3 = eventfd(0, 0);
    verifier(epoll_ctl(p, EPOLL_CTL_ADD, e3, &ev) == 0, "ADD d'un troisieme eventfd");
    int copie = dup(e3);
    close(e3);
    verifier(erreur(epoll_ctl(p, EPOLL_CTL_MOD, e3, &ev)) == EBADF, "son numero ferme : EBADF");
    verifier(epoll_ctl(p, EPOLL_CTL_ADD, copie, &ev) == 0, "le dup s'inscrit sous son propre numero");
    /* Fermer le dernier fait quitter le fichier de l'epoll : un eventfd neuf,
     * qui reprend le plus petit numero libre (celui du troisieme), s'inscrit
     * sans EEXIST. (Chez nous, il reprend aussi la place du fichier ferme
     * dans la table du noyau : une inscription restee la le ferait
     * refuser.) */
    close(copie);
    int e4 = eventfd(0, 0);
    verifier(e4 == e3 && epoll_ctl(p, EPOLL_CTL_ADD, e4, &ev) == 0, "un fichier ferme quitte l'epoll");
    close(o); close(r); close(u); close(zero); close(nul); close(d); close(f);
    close(e4); close(q); close(e); close(e2); close(p);
}

int main(void)
{
    compteurs();
    fichier_anonyme();
    surveillance();
    printf("[linux] evenements : toutes les verifications : %s\n", echecs ? "ECHEC" : "ok");
    return echecs != 0;
}
