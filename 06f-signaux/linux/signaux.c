/*
 * Les signaux enregistrés (6d) : rt_sigaction, rt_sigprocmask,
 * rt_sigpending, sigaltstack, kill, tkill, tgkill. Il tourne dans notre
 * noyau et sur l'hôte (make tests-hote) : chaque ligne doit dire « ok »
 * des deux côtés. Rien ici n'appelle de gestionnaire (notre noyau ne les
 * appelle qu'en 6f) : les signaux envoyés sont ignorés, ou bloqués puis
 * effacés.
 *
 * Les appels passent par syscall() quand la glibc changerait ce qu'on
 * veut voir : son sigaction() traduit sa propre structure et ajoute
 * SA_RESTORER ; ici, on parle au noyau avec la sienne.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static int echecs;

static void verifier(int ok, const char *quoi)
{
    printf("[linux] signaux : %s : %s\n", quoi, ok ? "ok" : "ECHEC");
    echecs += !ok;
}

/* La struct sigaction du noyau pour x86_64, celle de rt_sigaction. */
struct action_noyau {
    uint64_t gestionnaire;
    uint64_t drapeaux;
    uint64_t restaurateur;
    uint64_t masque;
};

#define DRAPEAU_RESTORER 0x04000000ULL
#define DRAPEAU_SIGINFO 0x4ULL
#define DRAPEAU_UNSUPPORTED 0x400ULL
#define BIT(s) (1ULL << ((s) - 1))
/* Rendre la pile de secours le temps d'un gestionnaire (linux/signal.h,
 * que la glibc n'expose pas). */
#define SS_AUTODISARM (1U << 31)

/* Le numéro d'erreur d'un appel système brut (0 s'il a réussi). */
static long erreur(long r)
{
    return r < 0 ? errno : 0;
}

static long action(int sig, const struct action_noyau *nouvelle, struct action_noyau *ancienne, long taille)
{
    return erreur(syscall(SYS_rt_sigaction, sig, nouvelle, ancienne, taille));
}

static long masque(int comment, const uint64_t *ensemble, uint64_t *ancien, long taille)
{
    return erreur(syscall(SYS_rt_sigprocmask, comment, ensemble, ancien, taille));
}

static uint64_t en_attente(void)
{
    uint64_t e = 0;
    syscall(SYS_rt_sigpending, &e, 8);
    return e;
}

static void actions(void)
{
    struct action_noyau a = { (uint64_t)SIG_IGN, DRAPEAU_RESTORER | DRAPEAU_SIGINFO | 0xffffffff00000000ULL | DRAPEAU_UNSUPPORTED,
                              0x1234, ~0ULL };
    struct action_noyau lue;
    verifier(action(SIGUSR1, &a, NULL, 8) == 0, "rt_sigaction avec des drapeaux inconnus : accepte");
    memset(&lue, 0, sizeof lue);
    verifier(action(SIGUSR1, NULL, &lue, 8) == 0 && lue.drapeaux == (DRAPEAU_RESTORER | DRAPEAU_SIGINFO),
             "les drapeaux inconnus (et SA_UNSUPPORTED) relus effaces");
    verifier(lue.gestionnaire == (uint64_t)SIG_IGN && lue.restaurateur == 0x1234,
             "le gestionnaire et le restaurateur relus");
    verifier(lue.masque == ~(BIT(SIGKILL) | BIT(SIGSTOP)), "SIGKILL et SIGSTOP retires du masque de l'action");

    struct action_noyau b = { (uint64_t)SIG_DFL, DRAPEAU_RESTORER, 0, 0 };
    memset(&lue, 0, sizeof lue);
    verifier(action(SIGUSR1, &b, &lue, 8) == 0 && lue.gestionnaire == (uint64_t)SIG_IGN,
             "l'ancienne action rendue en posant la nouvelle");
    verifier(action(SIGKILL, &b, NULL, 8) == EINVAL, "une action pour SIGKILL : EINVAL");
    verifier(action(SIGSTOP, &b, NULL, 8) == EINVAL, "une action pour SIGSTOP : EINVAL");
    memset(&lue, 0xff, sizeof lue);
    verifier(action(SIGKILL, NULL, &lue, 8) == 0 && lue.gestionnaire == (uint64_t)SIG_DFL,
             "l'action de SIGKILL se lit (SIG_DFL)");
    verifier(action(0, NULL, &lue, 8) == EINVAL, "le signal 0 : EINVAL");
    verifier(action(65, NULL, &lue, 8) == EINVAL, "le signal 65 : EINVAL");
    verifier(action(64, NULL, &lue, 8) == 0, "le signal 64 se lit");
    verifier(action(SIGUSR1, NULL, &lue, 4) == EINVAL, "un masque de 4 octets : EINVAL");
    verifier(action(SIGUSR1, (void *)8, NULL, 8) == EFAULT, "une action a une adresse invalide : EFAULT");
}

static void masques(void)
{
    uint64_t tout = ~0ULL, rien = 0, lu = 0;
    verifier(masque(7, NULL, &lu, 8) == 0, "rt_sigprocmask : un `comment` invalide sans ensemble : 0");
    verifier(masque(7, &tout, NULL, 8) == EINVAL, "un `comment` invalide avec un ensemble : EINVAL");
    verifier(masque(SIG_BLOCK, &tout, NULL, 4) == EINVAL, "un masque de 4 octets : EINVAL");
    verifier(masque(SIG_SETMASK, &tout, NULL, 8) == 0 && masque(SIG_BLOCK, NULL, &lu, 8) == 0
             && lu == ~(BIT(SIGKILL) | BIT(SIGSTOP)), "tout bloquer, sauf SIGKILL et SIGSTOP (retires en silence)");
    uint64_t usr = BIT(SIGUSR1) | BIT(SIGUSR2);
    verifier(masque(SIG_UNBLOCK, &usr, &lu, 8) == 0 && masque(SIG_BLOCK, NULL, &lu, 8) == 0
             && lu == (~(BIT(SIGKILL) | BIT(SIGSTOP)) & ~usr), "SIG_UNBLOCK");
    verifier(masque(SIG_SETMASK, &rien, NULL, 8) == 0 && masque(SIG_BLOCK, &usr, &lu, 8) == 0 && lu == 0
             && masque(SIG_BLOCK, NULL, &lu, 8) == 0 && lu == usr, "SIG_SETMASK puis SIG_BLOCK, l'ancien rendu");
    masque(SIG_SETMASK, &rien, NULL, 8);

    uint64_t e;
    verifier(syscall(SYS_rt_sigpending, &e, 0) == 0 && syscall(SYS_rt_sigpending, &e, 4) == 0,
             "rt_sigpending de 0 et de 4 octets : 0");
    verifier(erreur(syscall(SYS_rt_sigpending, &e, 16)) == EINVAL, "rt_sigpending de 16 octets : EINVAL");
}

static void attente(void)
{
    uint64_t winch = BIT(SIGWINCH), usr2 = BIT(SIGUSR2), rien = 0;
    pid_t moi = getpid();
    /* SIGWINCH est ignoré par défaut : bloqué, il attend quand même. */
    masque(SIG_BLOCK, &winch, NULL, 8);
    verifier(kill(moi, SIGWINCH) == 0 && en_attente() == winch, "SIGWINCH bloque puis envoye : en attente");
    masque(SIG_UNBLOCK, &winch, NULL, 8);
    verifier(en_attente() == 0, "SIGWINCH debloque : livre (ignore par defaut), plus en attente");

    /* SIGUSR2 termine par défaut : bloqué, envoyé, puis ignoré, il est
     * effacé (POSIX), et le débloquer ne fait plus rien. L'action par
     * défaut est remise AVANT de débloquer : si l'attente n'avait pas été
     * effacée, SIGUSR2 tuerait le programme (code 140) et la dernière
     * ligne manquerait. */
    masque(SIG_BLOCK, &usr2, NULL, 8);
    verifier(raise(SIGUSR2) == 0 && en_attente() == usr2, "SIGUSR2 bloque puis envoye (raise) : en attente");
    struct action_noyau ign = { (uint64_t)SIG_IGN, DRAPEAU_RESTORER, 0, 0 };
    struct action_noyau dfl = { (uint64_t)SIG_DFL, DRAPEAU_RESTORER, 0, 0 };
    action(SIGUSR2, &ign, NULL, 8);
    verifier(en_attente() == 0, "SIGUSR2 en attente puis ignore : efface");
    action(SIGUSR2, &dfl, NULL, 8);
    masque(SIG_SETMASK, &rien, NULL, 8);
    verifier(en_attente() == 0, "SIGUSR2 remis par defaut puis debloque : rien ne se passe");

    /* Ignoré et non bloqué : jeté dès l'envoi. */
    signal(SIGPIPE, SIG_IGN);
    verifier(raise(SIGPIPE) == 0 && en_attente() == 0, "SIGPIPE ignore puis envoye : jete, le programme continue");
}

static void envois(void)
{
    pid_t moi = getpid();
    pid_t fil = (pid_t)syscall(SYS_gettid);
    verifier(kill(moi, 0) == 0, "kill(soi, 0) : 0");
    verifier(kill(moi, 65) == -1 && errno == EINVAL, "kill(soi, 65) : EINVAL");
    verifier(kill(0, 0) == 0, "kill(0, 0), son groupe : 0");
    verifier(kill(2147483000, 0) == -1 && errno == ESRCH, "kill d'un processus qui n'existe pas : ESRCH");
    verifier(syscall(SYS_tgkill, moi, fil, 0) == 0, "tgkill(soi, soi, 0) : 0");
    verifier(erreur(syscall(SYS_tgkill, 0, fil, 0)) == EINVAL, "tgkill(0, ...) : EINVAL");
    verifier(erreur(syscall(SYS_tkill, 0, 0)) == EINVAL, "tkill(0, ...) : EINVAL");
    verifier(erreur(syscall(SYS_tgkill, moi, 2147483000, 0)) == ESRCH, "tgkill d'un fil qui n'existe pas : ESRCH");
    verifier(syscall(SYS_tkill, fil, 0) == 0, "tkill(soi, 0) : 0");
    verifier(moi != 1 && getppid() != 0 && fil == moi, "un pid qui n'est pas 1, un parent, un seul fil");
}

static void pile_de_secours(void)
{
    static char pile[8192];
    stack_t s, lue;
    memset(&lue, 0xff, sizeof lue);
    verifier(sigaltstack(NULL, &lue) == 0 && lue.ss_sp == NULL && lue.ss_flags == SS_DISABLE && lue.ss_size == 0,
             "sigaltstack : au depart {NULL, SS_DISABLE, 0}");
    /* Linux garde les drapeaux tels que posés (0 au départ) : redonner la
     * pile qu'on a ne change rien et réussit, sans vérifier la taille. */
    s = (stack_t){ .ss_sp = NULL, .ss_flags = 0, .ss_size = 0 };
    verifier(sigaltstack(&s, NULL) == 0, "redonner {NULL, 0, 0}, la pile de depart : 0");
    s = (stack_t){ .ss_sp = pile, .ss_flags = 0, .ss_size = 2047 };
    verifier(sigaltstack(&s, NULL) == -1 && errno == ENOMEM, "2047 octets : ENOMEM");
    s.ss_size = 2048;
    verifier(sigaltstack(&s, NULL) == 0 && sigaltstack(NULL, &lue) == 0 && lue.ss_sp == pile && lue.ss_size == 2048
             && lue.ss_flags == 0, "2048 octets : accepte, relu");
    s.ss_flags = 77;
    verifier(sigaltstack(&s, NULL) == -1 && errno == EINVAL, "des drapeaux inconnus : EINVAL");
    s = (stack_t){ .ss_sp = pile + 3, .ss_flags = (int)(SS_ONSTACK | SS_AUTODISARM), .ss_size = 4096 };
    verifier(sigaltstack(&s, NULL) == 0 && sigaltstack(NULL, &lue) == 0 && lue.ss_sp == pile + 3
             && (unsigned)lue.ss_flags == SS_AUTODISARM, "adresse non alignee et SS_ONSTACK acceptes, SS_AUTODISARM garde");
    s = (stack_t){ .ss_sp = pile, .ss_flags = SS_DISABLE, .ss_size = 4096 };
    verifier(sigaltstack(&s, NULL) == 0 && sigaltstack(NULL, &lue) == 0 && lue.ss_sp == NULL && lue.ss_size == 0
             && lue.ss_flags == SS_DISABLE, "SS_DISABLE remet l'adresse et la taille a 0");
}

int main(void)
{
    actions();
    masques();
    attente();
    envois();
    pile_de_secours();
    printf("[linux] signaux : toutes les verifications : %s\n", echecs ? "ECHEC" : "ok");
    return echecs != 0;
}
