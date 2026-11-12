/*
 * Les signaux enregistrés (6d) : rt_sigaction, rt_sigprocmask,
 * rt_sigpending, sigaltstack, kill, tkill, tgkill ; puis leur file et leur
 * siginfo (6f) : rt_sigqueueinfo, rt_tgsigqueueinfo, rt_sigtimedwait, et
 * RLIMIT_SIGPENDING ; puis signalfd (les soldes d'avant 6k). Il tourne dans
 * notre noyau et sur l'hôte (make tests-hote) : chaque ligne doit dire
 * « ok » des deux côtés. Presque rien ici n'appelle de gestionnaire
 * (gestionnaires.c le fait ; ici, seulement un read de signalfd
 * interrompu) : les signaux envoyés sont ignorés, ou bloqués puis effacés,
 * ou pris par rt_sigtimedwait ou par un signalfd.
 *
 * Trois autres façons de le lancer, à la suite (racine/etc/demarrage, et
 * make tests-hote) : « signaux garder & », « signaux transmettre », puis
 * « signaux relacher » : l'epoll et le signalfd d'un processus fini, gardés
 * par un autre (voir `garder`).
 *
 * Les appels passent par syscall() quand la glibc changerait ce qu'on
 * veut voir : son sigaction() traduit sa propre structure et ajoute
 * SA_RESTORER ; ici, on parle au noyau avec la sienne.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static int echecs;
/* Le nom des lignes : « signaux », ou « signaux garder »... */
static const char *nom = "signaux";

static void verifier(int ok, const char *quoi)
{
    printf("[linux] %s : %s : %s\n", nom, quoi, ok ? "ok" : "ECHEC");
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
     * pile qu'on a ne change rien et réussit, sans vérifier la taille. Sur
     * l'hôte, ces drapeaux viennent de nos ancêtres, exec n'y touche pas : un
     * fil sans pile de secours laisse SS_DISABLE, et la taille est alors
     * vérifiée (mesuré sous un init lancé par le noyau : ENOMEM). */
    s = (stack_t){ .ss_sp = NULL, .ss_flags = 0, .ss_size = 0 };
    int redonne = sigaltstack(&s, NULL) == 0 ? 0 : errno;
    verifier(redonne == 0 || (access("/etc/bonjour.txt", F_OK) != 0 && redonne == ENOMEM),
             "redonner {NULL, 0, 0}, la pile de depart : 0");
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

/* rt_sigtimedwait brut : `ensemble` attendu, `info` rempli, `delai` (NULL :
 * sans fin). Rend le signal pris, ou -errno. */
static long attendre(uint64_t ensemble, siginfo_t *info, const struct timespec *delai)
{
    long r = syscall(SYS_rt_sigtimedwait, &ensemble, info, delai, 8);
    return r < 0 ? -errno : r;
}

static long long maintenant_ns(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000000000LL + t.tv_nsec;
}

/* rt_sigqueueinfo brut, avec un siginfo écrit à la main. */
static long mettre_en_file(pid_t pid, int sig, int code, int valeur, int octet_100)
{
    union {
        siginfo_t si;
        unsigned char o[128];
    } u;
    memset(&u, 0, sizeof u);
    u.si.si_signo = 99;
    u.si.si_code = code;
    u.si.si_pid = 4242;
    u.si.si_uid = 77;
    u.si.si_value.sival_int = valeur;
    u.o[100] = (unsigned char)octet_100;
    return erreur(syscall(SYS_rt_sigqueueinfo, pid, sig, &u.si));
}

/* Un fil secondaire : rt_sigqueueinfo en SI_USER vers son propre processus
 * est refusé (Linux compare au numéro du fil appelant), en SI_QUEUE non. */
static long refus_du_fil, accepte_du_fil;

static void *fil_secondaire(void *rien)
{
    (void)rien;
    refus_du_fil = mettre_en_file(getpid(), SIGUSR1, SI_USER, 0, 0);
    accepte_du_fil = mettre_en_file(getpid(), SIGUSR1, SI_QUEUE, 0, 0);
    return NULL;
}

/* Un autre fil envoie `sig` au fil principal, 50 ms plus tard. */
static pid_t fil_principal;

static void *envoyer_plus_tard(void *sig)
{
    struct timespec cinquante = { 0, 50000000 };
    nanosleep(&cinquante, NULL);
    syscall(SYS_tgkill, getpid(), fil_principal, (int)(long)sig);
    return NULL;
}

/* La file des signaux et leur siginfo (6f), lus par rt_sigtimedwait : qui
 * envoie quoi, combien d'exemplaires restent, ce que fait la limite. Tout
 * est bloqué avant d'être envoyé : sans gestionnaire, un signal non
 * bloqué tuerait le programme. */
static void files(void)
{
    pid_t moi = getpid(), fil = (pid_t)syscall(SYS_gettid);
    uid_t uid = getuid();
    int rt = SIGRTMIN + 3;
    uint64_t usr1 = BIT(SIGUSR1), tous = BIT(SIGUSR1) | BIT(SIGWINCH) | BIT(rt) | BIT(SIGRTMIN + 4), rien = 0;
    masque(SIG_BLOCK, &tous, NULL, 8);
    siginfo_t si;
    struct timespec zero = { 0, 0 };

    kill(moi, SIGUSR1);
    memset(&si, 0xff, sizeof si);
    verifier(attendre(usr1, &si, &zero) == SIGUSR1 && si.si_signo == SIGUSR1 && si.si_code == SI_USER && si.si_errno == 0
             && si.si_pid == moi && si.si_uid == uid, "kill : SI_USER, le pid et l'uid de qui envoie");
    syscall(SYS_tgkill, moi, fil, SIGUSR1);
    verifier(attendre(usr1, &si, &zero) == SIGUSR1 && si.si_code == SI_TKILL && si.si_pid == moi && si.si_uid == uid,
             "tgkill : SI_TKILL");
    union sigval v = { .sival_int = 42 };
    sigqueue(moi, rt, v);
    verifier(attendre(BIT(rt), &si, &zero) == rt && si.si_code == SI_QUEUE && si.si_value.sival_int == 42 && si.si_pid == moi,
             "sigqueue : SI_QUEUE et sa valeur");
    unsigned char *o = (unsigned char *)&si;
    int reste_nul = 1;
    for (int i = 48; i < 128; i++)
        reste_nul &= o[i] == 0;
    verifier(reste_nul, "le siginfo rendu : 128 octets, nuls apres les 48 que garde le noyau");

    /* rt_sigqueueinfo : un siginfo à soi, tel quel (sauf si_signo) ; se
     * faire passer pour kill ou tkill vers un autre : EPERM, avant même de
     * chercher le processus ; une disposition inconnue (si_code -100) ne
     * passe que si le reste du siginfo est nul (E2BIG). */
    verifier(mettre_en_file(moi, SIGUSR1, SI_USER, 0, 0) == 0 && attendre(usr1, &si, &zero) == SIGUSR1
             && si.si_signo == SIGUSR1 && si.si_code == SI_USER && si.si_pid == 4242 && si.si_uid == 77,
             "rt_sigqueueinfo vers soi : le siginfo donne, si_signo corrige");
    verifier(mettre_en_file(1, SIGUSR1, SI_USER, 0, 0) == EPERM && mettre_en_file(1, SIGUSR1, SI_TKILL, 0, 0) == EPERM,
             "rt_sigqueueinfo vers un autre, en SI_USER ou SI_TKILL : EPERM");
    verifier(mettre_en_file(2147483000, SIGUSR1, SI_QUEUE, 0, 0) == ESRCH, "en SI_QUEUE vers un processus absent : ESRCH");
    pthread_t f;
    pthread_create(&f, NULL, fil_secondaire, NULL);
    pthread_join(f, NULL);
    verifier(refus_du_fil == EPERM && accepte_du_fil == 0 && attendre(usr1, &si, &zero) == SIGUSR1 && si.si_code == SI_QUEUE,
             "d'un fil secondaire vers son processus : SI_USER refuse (EPERM, compare au fil), SI_QUEUE accepte");
    verifier(mettre_en_file(moi, SIGUSR1, -100, 0, 1) == E2BIG && mettre_en_file(moi, SIGUSR1, SI_QUEUE, 0, 1) == 0
             && attendre(usr1, &si, &zero) == SIGUSR1, "si_code inconnu (-100) et un octet au-dela des 48 : E2BIG ; connu : accepte");
    verifier(mettre_en_file(moi, 65, SI_QUEUE, 0, 0) == EINVAL, "rt_sigqueueinfo du signal 65 : EINVAL");
    uint64_t sys = BIT(SIGSYS);
    masque(SIG_BLOCK, &sys, NULL, 8);
    verifier(mettre_en_file(moi, SIGSYS, 2, 0, 1) == 0 && attendre(sys, &si, &zero) == SIGSYS && si.si_code == 2
                 && mettre_en_file(moi, SIGSYS, 3, 0, 1) == E2BIG,
             "SIGSYS : si_code 2 (SYS_USER_DISPATCH) connu, 3 non (E2BIG)");
    masque(SIG_UNBLOCK, &sys, NULL, 8);
    union {
        siginfo_t si;
        unsigned char o[128];
    } u;
    memset(&u, 0, sizeof u);
    u.si.si_code = SI_QUEUE;
    verifier(erreur(syscall(SYS_rt_tgsigqueueinfo, moi, fil, SIGUSR1, &u.si)) == 0 && attendre(usr1, &si, &zero) == SIGUSR1
             && si.si_code == SI_QUEUE, "rt_tgsigqueueinfo vers soi : accepte");
    verifier(erreur(syscall(SYS_rt_tgsigqueueinfo, 0, fil, SIGUSR1, &u.si)) == EINVAL
             && erreur(syscall(SYS_rt_tgsigqueueinfo, moi, 2147483000, SIGUSR1, &u.si)) == ESRCH,
             "rt_tgsigqueueinfo : tgid nul EINVAL, fil absent ESRCH");
    verifier(erreur(syscall(SYS_rt_sigqueueinfo, moi, SIGUSR1, (void *)8)) == EFAULT, "rt_sigqueueinfo, siginfo invalide : EFAULT");

    /* La file : trois temps réel et trois SIGWINCH bloqués, puis pris un
     * par un : les trois temps réel (dans l'ordre d'envoi), un seul SIGWINCH
     * (un signal ordinaire n'est en file qu'une fois), et lui d'abord (le
     * plus petit numéro passe le premier). */
    for (int i = 0; i < 3; i++) {
        v.sival_int = i;
        sigqueue(moi, rt, v);
        kill(moi, SIGWINCH);
    }
    long a = attendre(tous, &si, &zero);
    int ordre = a == SIGWINCH;
    for (int i = 0; i < 3; i++)
        ordre &= attendre(tous, &si, &zero) == rt && si.si_value.sival_int == i;
    verifier(ordre && attendre(tous, &si, &zero) == -EAGAIN,
             "3 temps reel et 3 SIGWINCH : SIGWINCH une fois, d'abord, puis les 3 temps reel dans l'ordre");

    /* La limite : à 0, plus aucun temps réel ne se met en file. sigqueue rend
     * EAGAIN ; kill réussit, mais le signal arrive sans son siginfo (SI_USER,
     * pid 0) ; un ordinaire passe toujours, avec le sien. */
    struct rlimit lim, zero_lim;
    getrlimit(RLIMIT_SIGPENDING, &lim);
    verifier(lim.rlim_cur == lim.rlim_max && lim.rlim_cur > 0 && lim.rlim_cur != RLIM_INFINITY,
             "RLIMIT_SIGPENDING : une limite finie, la meme pour les deux");
    zero_lim = (struct rlimit){ 0, lim.rlim_max };
    setrlimit(RLIMIT_SIGPENDING, &zero_lim);
    v.sival_int = 7;
    int refuse = sigqueue(moi, rt, v) == -1 && errno == EAGAIN;
    int tue = kill(moi, SIGRTMIN + 4) == 0 && attendre(BIT(SIGRTMIN + 4), &si, &zero) == SIGRTMIN + 4 && si.si_code == SI_USER
              && si.si_pid == 0;
    int ordinaire = kill(moi, SIGUSR1) == 0 && attendre(usr1, &si, &zero) == SIGUSR1 && si.si_pid == moi;
    setrlimit(RLIMIT_SIGPENDING, &lim);
    verifier(refuse && tue && ordinaire,
             "RLIMIT_SIGPENDING a 0 : sigqueue EAGAIN, kill d'un temps reel sans siginfo, un ordinaire avec le sien");

    /* rt_sigtimedwait : un délai nul rend EAGAIN tout de suite, 50 ms au
     * moins 50 ms plus tard ; les erreurs. */
    struct timespec cinquante = { 0, 50000000 }, faux = { 0, 1000000000 };
    long long t = maintenant_ns();
    verifier(attendre(usr1, &si, &cinquante) == -EAGAIN && maintenant_ns() - t >= 50000000, "rt_sigtimedwait 50 ms : EAGAIN, pas avant");
    verifier(attendre(usr1, &si, &faux) == -EINVAL, "un delai de 1e9 ns : EINVAL");
    verifier(erreur(syscall(SYS_rt_sigtimedwait, &usr1, &si, &zero, 4)) == EINVAL, "une taille de masque de 4 : EINVAL");
    verifier(erreur(syscall(SYS_rt_sigtimedwait, (void *)8, &si, &zero, 8)) == EFAULT, "un masque invalide : EFAULT");
    kill(moi, SIGUSR1);
    verifier(attendre(usr1, (void *)8, &zero) == -EFAULT && en_attente() == 0, "un siginfo invalide : EFAULT, le signal pris quand meme");
    kill(moi, SIGUSR1);
    verifier(attendre(usr1, NULL, &zero) == SIGUSR1, "sans siginfo (NULL) : le signal");
    /* Un signal ignoré (SIGWINCH par défaut, SIGUSR2 à SIG_IGN), bloqué et
     * attendu, envoyé par un autre fil pendant l'attente : pris. Linux garde
     * le vrai masque le temps de l'attente (`real_blocked`), et un signal
     * bloqué n'est jamais jeté à l'envoi. */
    struct timespec une = { 1, 0 };
    uint64_t usr2 = BIT(SIGUSR2);
    fil_principal = fil;
    pthread_create(&f, NULL, envoyer_plus_tard, (void *)(long)SIGWINCH);
    long winch = attendre(BIT(SIGWINCH), &si, &une);
    pthread_join(f, NULL);
    masque(SIG_BLOCK, &usr2, NULL, 8);
    signal(SIGUSR2, SIG_IGN);
    pthread_create(&f, NULL, envoyer_plus_tard, (void *)(long)SIGUSR2);
    long ignore = attendre(usr2, &si, &une);
    pthread_join(f, NULL);
    signal(SIGUSR2, SIG_DFL);
    verifier(winch == SIGWINCH && ignore == SIGUSR2, "un signal ignore, attendu par rt_sigtimedwait, envoye pendant l'attente : pris");
    masque(SIG_SETMASK, &rien, NULL, 8);
}

/* signalfd (les soldes d'avant 6k) : les signaux d'un masque, lus comme un
 * fichier. Le signalfd_siginfo de 128 octets n'a pas la disposition du
 * siginfo_t : écrit ici champ par champ, pour vérifier chacun. */
struct ssi {
    uint32_t signo;
    int32_t err;
    int32_t code;
    uint32_t pid;
    uint32_t uid;
    int32_t fd;
    uint32_t tid;
    uint32_t band;
    uint32_t overrun;
    uint32_t trapno;
    int32_t status;
    int32_t entier;
    uint64_t ptr;
    uint64_t utime;
    uint64_t stime;
    uint64_t addr;
    uint16_t addr_lsb;
    uint16_t pad2;
    int32_t appel;
    uint64_t call_addr;
    uint32_t arch;
    uint8_t pad[28];
};
_Static_assert(sizeof(struct ssi) == 128, "signalfd_siginfo : 128 octets");

/* signalfd4 et signalfd bruts : le descripteur, ou -errno. */
static long sfd4(int fd, const void *m, long taille, int drapeaux)
{
    long r = syscall(SYS_signalfd4, fd, m, taille, drapeaux);
    return r < 0 ? -errno : r;
}

static long sfd(int fd, const void *m, long taille)
{
    long r = syscall(SYS_signalfd, fd, m, taille);
    return r < 0 ? -errno : r;
}

/* read : le nombre d'octets, ou -errno. */
static long lire(int fd, void *o, size_t n)
{
    long r = read(fd, o, n);
    return r < 0 ? -errno : r;
}

static void dormir_ms(long ms)
{
    struct timespec t = { ms / 1000, (ms % 1000) * 1000000 };
    while (nanosleep(&t, &t) != 0)
        ;
}

static void signalfd_creation(void)
{
    uint64_t usr1 = BIT(SIGUSR1), rien = 0;
    verifier(sfd4(-1, &usr1, 4, 0) == -EINVAL && sfd4(-1, (void *)8, 4, 0) == -EINVAL && sfd(-1, &usr1, 16) == -EINVAL,
             "signalfd4 et signalfd, une taille de masque de 4 ou 16 : EINVAL, avant de lire le masque");
    verifier(sfd4(-1, (void *)8, 8, 0) == -EFAULT && sfd4(-1, (void *)8, 8, 0x40) == -EFAULT && sfd4(-1, &usr1, 8, 0x40) == -EINVAL,
             "un masque invalide : EFAULT, avant un drapeau inconnu (EINVAL)");
    int a = (int)sfd4(-1, &usr1, 8, SFD_NONBLOCK | SFD_CLOEXEC), b = (int)sfd(-1, &rien, 8);
    char lien[64] = "", chemin[64];
    snprintf(chemin, sizeof chemin, "/proc/self/fd/%d", a);
    long n = readlink(chemin, lien, sizeof lien - 1);
    verifier(a >= 0 && b >= 0 && fcntl(a, F_GETFL) == (O_RDWR | O_NONBLOCK) && fcntl(a, F_GETFD) == FD_CLOEXEC
                 && fcntl(b, F_GETFL) == O_RDWR && fcntl(b, F_GETFD) == 0 && n == 21 && memcmp(lien, "anon_inode:[signalfd]", 21) == 0,
             "creation : O_RDWR, plus O_NONBLOCK et FD_CLOEXEC s'ils sont demandes ; anon_inode:[signalfd]");
    /* Un nouveau masque pour un signalfd : son numéro rendu ; les drapeaux
     * sont vérifiés, mais pas appliqués. */
    verifier(sfd4(b, &usr1, 8, SFD_NONBLOCK | SFD_CLOEXEC) == b && fcntl(b, F_GETFL) == O_RDWR && fcntl(b, F_GETFD) == 0
                 && sfd(b, &rien, 8) == b,
             "un nouveau masque : le meme descripteur, ses drapeaux inchanges");
    int ev = eventfd(0, 0), chemin_fd = open("/", O_PATH);
    verifier(sfd4(ev, &usr1, 8, 0) == -EINVAL && sfd4(9999, &usr1, 8, 0) == -EBADF && sfd4(-2, &usr1, 8, 0) == -EBADF
                 && sfd4(chemin_fd, &usr1, 8, 0) == -EBADF,
             "un descripteur qui n'est pas un signalfd : EINVAL ; ferme, -2 ou O_PATH : EBADF");
    verifier(sfd4(9999, (void *)8, 8, 0) == -EFAULT && sfd4(9999, &usr1, 8, 0x40) == -EINVAL,
             "le masque et les drapeaux sont verifies avant le descripteur");
    close(ev);
    close(chemin_fd);
    struct ssi s;
    int nb = 0;
    verifier(lire(a, &s, 127) == -EINVAL && lire(a, &s, 0) == -EINVAL && lire(a, &s, 128) == -EAGAIN,
             "read de moins de 128 octets (0 compris) : EINVAL ; rien en attente, non bloquant : EAGAIN");
    long w = write(a, &s, 128);
    int ew = errno;
    long p = pread(a, &s, 128, 0);
    int ep = errno;
    verifier(w == -1 && ew == EINVAL && lseek(a, 0, SEEK_CUR) == 0 && p == -1 && ep == ESPIPE, "write : EINVAL ; lseek : 0 ; pread : ESPIPE");
    long i = ioctl(a, FIONREAD, &nb);
    int ei = errno;
    verifier(i == -1 && ei == ENOTTY && ioctl(a, FIONBIO, &nb) == 0 && fcntl(a, F_GETFL) == O_RDWR,
             "ioctl : FIONREAD ENOTTY, FIONBIO change O_NONBLOCK");
    close(a);
    close(b);
}

/* Un fil qui lit un signalfd (bloquant ou non), un signal débloqué le temps
 * de sa lecture (0 : aucun). */
static int fd_du_fil, debloque_du_fil;
static volatile pid_t tid_du_fil;
static volatile int fil_pret, fil_fini;
static long lu_par_le_fil;
static struct ssi ssi_du_fil;

static void *lecteur(void *rien)
{
    if (debloque_du_fil) {
        uint64_t d = BIT(debloque_du_fil);
        masque(SIG_UNBLOCK, &d, NULL, 8);
    }
    tid_du_fil = (pid_t)syscall(SYS_gettid);
    __atomic_store_n(&fil_pret, 1, __ATOMIC_SEQ_CST);
    lu_par_le_fil = lire(fd_du_fil, &ssi_du_fil, sizeof ssi_du_fil);
    __atomic_store_n(&fil_fini, 1, __ATOMIC_SEQ_CST);
    return rien;
}

static void lancer_lecteur(pthread_t *f, int fd, int debloque)
{
    fd_du_fil = fd;
    debloque_du_fil = debloque;
    fil_pret = fil_fini = 0;
    lu_par_le_fil = 0;
    pthread_create(f, NULL, lecteur, NULL);
    while (!__atomic_load_n(&fil_pret, __ATOMIC_SEQ_CST))
        dormir_ms(1);
    dormir_ms(50);
}

/* Un autre fil envoie `sig` au processus, 50 ms plus tard. */
static void *tuer_plus_tard(void *sig)
{
    dormir_ms(50);
    kill(getpid(), (int)(long)sig);
    return NULL;
}

static volatile int vus_usr2;

static void sur_usr2(int sig)
{
    (void)sig;
    vus_usr2++;
}

static void signalfd_lecture(void)
{
    pid_t moi = getpid();
    uid_t uid = getuid();
    siginfo_t si;
    struct timespec zero = { 0, 0 };
    int rt = SIGRTMIN + 2;
    uint64_t bloques = BIT(SIGUSR1) | BIT(SIGUSR2) | BIT(SIGSEGV) | BIT(rt), ancien, m = BIT(SIGUSR1) | BIT(SIGSEGV) | BIT(rt);
    masque(SIG_BLOCK, &bloques, &ancien, 8);
    int fd = (int)sfd4(-1, &m, 8, SFD_NONBLOCK);
    struct ssi s[3], a;
    memset(&a, 0, sizeof a);
    a.signo = SIGUSR1;
    a.code = SI_USER;
    a.pid = (uint32_t)moi;
    a.uid = uid;
    kill(moi, SIGUSR1);
    verifier(lire(fd, s, sizeof s[0]) == 128 && memcmp(&s[0], &a, 128) == 0 && en_attente() == 0,
             "kill : SI_USER, ssi_pid et ssi_uid, le reste nul ; le signal pris");
    kill(moi, SIGUSR2);
    verifier(lire(fd, s, 128) == -EAGAIN && en_attente() == BIT(SIGUSR2), "un signal hors du masque : laisse en attente");
    attendre(BIT(SIGUSR2), &si, &zero);

    /* Trois signaux, 300 octets : deux rendus (256 octets), dans l'ordre de
     * la file ; le troisième au read suivant. */
    union sigval v;
    kill(moi, SIGUSR1);
    v.sival_int = 10;
    sigqueue(moi, rt, v);
    v.sival_int = 11;
    sigqueue(moi, rt, v);
    char tampon[300];
    long n1 = lire(fd, tampon, sizeof tampon);
    memcpy(s, tampon, 256);
    long n2 = lire(fd, &s[2], 128);
    verifier(n1 == 256 && n2 == 128 && s[0].signo == SIGUSR1 && s[1].signo == (uint32_t)rt && s[1].code == SI_QUEUE
                 && s[1].entier == 10 && s[1].pid == (uint32_t)moi && s[2].entier == 11 && lire(fd, s, 128) == -EAGAIN,
             "3 signaux et 300 octets : 256 octets, les deux premiers ; le troisieme ensuite");

    /* readv : 200 octets en trois morceaux (60, 60, 80) ; un seul signal
     * tient, écrit d'un morceau à l'autre. */
    struct ssi r;
    memset(&r, 0x55, sizeof r);
    char reste[80];
    struct iovec iov[3] = { { &r, 60 }, { (char *)&r + 60, 60 }, { reste, 80 } };
    kill(moi, SIGUSR1);
    long nv = readv(fd, iov, 3);
    memcpy((char *)&r + 120, reste, 8);
    verifier(nv == 128 && memcmp(&r, &a, 128) == 0, "readv de 200 octets en trois morceaux : 128 octets, d'un morceau a l'autre");

    /* Une adresse invalide : EFAULT, le signal perdu. Deux signaux dont le
     * second ne peut pas s'écrire (la page suivante n'existe pas) : le
     * premier rendu, le second perdu. */
    kill(moi, SIGUSR1);
    verifier(lire(fd, (void *)8, 128) == -EFAULT && en_attente() == 0, "une adresse invalide : EFAULT, le signal perdu");
    char *page = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    munmap(page + 4096, 4096);
    kill(moi, SIGUSR1);
    v.sival_int = 12;
    sigqueue(moi, rt, v);
    long nf = lire(fd, page + 4096 - 128, 256);
    verifier(nf == 128 && ((struct ssi *)(page + 4096 - 128))->signo == SIGUSR1 && en_attente() == 0,
             "deux signaux, le second ne peut pas s'ecrire : 128 octets, le second perdu");
    munmap(page, 4096);

    /* Les synchrones d'abord : SIGSEGV, mis en file après SIGUSR1, sort le
     * premier. */
    kill(moi, SIGUSR1);
    v.sival_int = 0;
    sigqueue(moi, SIGSEGV, v);
    verifier(lire(fd, s, 256) == 256 && s[0].signo == SIGSEGV && s[1].signo == SIGUSR1, "SIGSEGV (synchrone) avant SIGUSR1");

    /* Un signal envoyé à un fil : ce fil le lit, pas un autre ; poll de
     * même (POLLIN seul : signalfd ne dit rien d'autre). */
    pthread_t f;
    struct pollfd pf = { fd, POLLIN | POLLOUT | POLLPRI, 0 };
    verifier(poll(&pf, 1, 0) == 0, "poll sans signal : rien");
    syscall(SYS_tgkill, moi, (pid_t)syscall(SYS_gettid), SIGUSR1);
    lancer_lecteur(&f, fd, 0);
    pthread_join(f, NULL);
    pf.revents = 0;
    int vu = poll(&pf, 1, 0) == 1 && pf.revents == POLLIN;
    verifier(lu_par_le_fil == -EAGAIN && vu && lire(fd, s, 128) == 128 && s[0].code == SI_TKILL,
             "tgkill au fil principal : un autre fil n'a rien a lire ; lui, POLLIN seul, puis SI_TKILL");

    /* epoll_wait réveillé par un signal qu'envoie un autre fil. */
    int e = epoll_create1(0);
    struct epoll_event ee = { EPOLLIN, { .u64 = 7 } }, re;
    epoll_ctl(e, EPOLL_CTL_ADD, fd, &ee);
    int vide = epoll_wait(e, &re, 1, 0) == 0;
    pthread_create(&f, NULL, tuer_plus_tard, (void *)(long)SIGUSR1);
    int k = epoll_wait(e, &re, 1, 5000);
    pthread_join(f, NULL);
    verifier(vide && k == 1 && re.events == EPOLLIN && re.data.u64 == 7 && lire(fd, s, 128) == 128,
             "epoll_wait reveille par un signal envoye par un autre fil : EPOLLIN");
    close(e);
    close(fd);

    /* Un read bloquant : réveillé par un signal envoyé au processus ; par un
     * nouveau masque qui couvre un signal déjà en attente ; interrompu par
     * un gestionnaire (EINTR), ou repris avec SA_RESTART. */
    int fb = (int)sfd4(-1, &m, 8, 0);
    pthread_create(&f, NULL, tuer_plus_tard, (void *)(long)SIGUSR1);
    long nb = lire(fb, s, 128);
    pthread_join(f, NULL);
    verifier(nb == 128 && s[0].signo == SIGUSR1, "read bloquant, reveille par un signal envoye au processus");
    kill(moi, SIGUSR2);
    lancer_lecteur(&f, fb, 0);
    uint64_t usr2 = BIT(SIGUSR2);
    sfd(fb, &usr2, 8);
    pthread_join(f, NULL);
    verifier(lu_par_le_fil == 128 && ssi_du_fil.signo == SIGUSR2 && en_attente() == 0,
             "read bloquant d'un fil, reveille par un nouveau masque : le signal deja en attente");
    sfd(fb, &m, 8);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = sur_usr2;
    sigaction(SIGUSR2, &sa, NULL);
    vus_usr2 = 0;
    lancer_lecteur(&f, fb, SIGUSR2);
    while (!__atomic_load_n(&fil_fini, __ATOMIC_SEQ_CST)) {
        syscall(SYS_tgkill, moi, tid_du_fil, SIGUSR2);
        dormir_ms(20);
    }
    pthread_join(f, NULL);
    verifier(lu_par_le_fil == -EINTR && vus_usr2 > 0, "read bloquant, un gestionnaire sans SA_RESTART : EINTR");
    sa.sa_flags = SA_RESTART;
    sigaction(SIGUSR2, &sa, NULL);
    vus_usr2 = 0;
    lancer_lecteur(&f, fb, SIGUSR2);
    for (int i = 0; i < 3; i++) {
        syscall(SYS_tgkill, moi, tid_du_fil, SIGUSR2);
        dormir_ms(20);
    }
    kill(moi, SIGUSR1);
    pthread_join(f, NULL);
    verifier(lu_par_le_fil == 128 && ssi_du_fil.signo == SIGUSR1 && vus_usr2 > 0,
             "read bloquant, un gestionnaire avec SA_RESTART : repris, puis le signal");
    signal(SIGUSR2, SIG_DFL);
    close(fb);
    masque(SIG_SETMASK, &ancien, NULL, 8);
}

/* Ce que signalfd doit rendre d'un siginfo du noyau (ses 48 octets), selon
 * sa disposition (le `siginfo_layout` de Linux). */
enum disposition { KILL, TIMER, POLL, FAULT, MCEERR, CHLD, RT, SYS };

static int32_t i32(const unsigned char *o, int n)
{
    int32_t x;
    memcpy(&x, o + n, 4);
    return x;
}

static int64_t i64(const unsigned char *o, int n)
{
    int64_t x;
    memcpy(&x, o + n, 8);
    return x;
}

static void attendu_de(const unsigned char *o, enum disposition d, struct ssi *a)
{
    memset(a, 0, sizeof *a);
    a->signo = (uint32_t)i32(o, 0);
    a->err = i32(o, 4);
    a->code = i32(o, 8);
    switch (d) {
    case KILL:
        a->pid = (uint32_t)i32(o, 16);
        a->uid = (uint32_t)i32(o, 20);
        break;
    case TIMER:
        a->tid = (uint32_t)i32(o, 16);
        a->overrun = (uint32_t)i32(o, 20);
        a->ptr = (uint64_t)i64(o, 24);
        a->entier = i32(o, 24);
        break;
    case POLL:
        a->band = (uint32_t)i64(o, 16);
        a->fd = i32(o, 24);
        break;
    case FAULT:
        a->addr = (uint64_t)i64(o, 16);
        break;
    case MCEERR:
        a->addr = (uint64_t)i64(o, 16);
        a->addr_lsb = (uint16_t)(int16_t)i32(o, 24);
        break;
    case CHLD:
        a->pid = (uint32_t)i32(o, 16);
        a->uid = (uint32_t)i32(o, 20);
        a->status = i32(o, 24);
        a->utime = (uint64_t)i64(o, 32);
        a->stime = (uint64_t)i64(o, 40);
        break;
    case RT:
        a->pid = (uint32_t)i32(o, 16);
        a->uid = (uint32_t)i32(o, 20);
        a->ptr = (uint64_t)i64(o, 24);
        a->entier = i32(o, 24);
        break;
    case SYS:
        a->call_addr = (uint64_t)i64(o, 16);
        a->appel = i32(o, 24);
        a->arch = (uint32_t)i32(o, 28);
        break;
    }
}

/* Chaque disposition, par un siginfo écrit à la main (rt_sigqueueinfo vers
 * soi accepte tout si_code) : ce que signalfd rend de chacun de ses octets.
 * Les si_code au-delà de ceux d'un signal tombent sur SIL_POLL jusqu'à 6
 * (NSIGPOLL), puis sur SIL_KILL ; un signal sans si_code propre, de même. */
static void signalfd_dispositions(void)
{
    static const struct {
        int sig, code;
        enum disposition d;
    } cas[] = {
        { SIGUSR1, SI_QUEUE, RT },     { SIGUSR1, SI_USER, KILL },   { SIGUSR1, SI_KERNEL, KILL }, { SIGUSR1, SI_TKILL, RT },
        { SIGUSR1, SI_TIMER, TIMER },  { SIGUSR1, SI_SIGIO, POLL },  { SIGUSR1, 3, POLL },         { SIGUSR1, 7, KILL },
        { SIGSEGV, SEGV_MAPERR, FAULT }, { SIGSEGV, 3, FAULT },      { SIGSEGV, 4, FAULT },        { SIGSEGV, 10, FAULT },
        { SIGSEGV, 11, KILL },         { SIGBUS, 4, MCEERR },        { SIGBUS, 5, MCEERR },        { SIGBUS, 6, POLL },
        { SIGTRAP, 6, FAULT },         { SIGILL, 11, FAULT },        { SIGILL, 12, KILL },         { SIGFPE, 15, FAULT },
        { SIGCHLD, CLD_EXITED, CHLD }, { SIGCHLD, 7, KILL },         { SIGIO, POLL_IN, POLL },     { SIGSYS, 1, SYS },
        { SIGSYS, 2, SYS },            { SIGSYS, 3, POLL },          { 35, 2, POLL },              { 35, 7, KILL },
    };
    uint64_t tous = ~0ULL & ~(BIT(SIGKILL) | BIT(SIGSTOP)), ancien;
    masque(SIG_BLOCK, &tous, &ancien, 8);
    int fd = (int)sfd4(-1, &tous, 8, SFD_NONBLOCK);
    int bons = 0;
    for (unsigned i = 0; i < sizeof cas / sizeof cas[0]; i++) {
        union {
            siginfo_t si;
            unsigned char o[128];
        } u;
        memset(&u, 0, sizeof u);
        for (int k = 4; k < 48; k++)
            u.o[k] = (unsigned char)(k * 37 + i);
        memcpy(u.o + 8, &cas[i].code, 4);
        long r = erreur(syscall(SYS_rt_sigqueueinfo, getpid(), cas[i].sig, &u.si));
        int32_t sig = cas[i].sig;
        memcpy(u.o, &sig, 4);
        struct ssi s, a;
        attendu_de(u.o, cas[i].d, &a);
        long n = lire(fd, &s, sizeof s);
        if (r == 0 && n == 128 && memcmp(&s, &a, 128) == 0)
            bons++;
        else
            printf("[linux] signaux : disposition, signal %d, si_code %d : envoi %ld, lu %ld\n", cas[i].sig, cas[i].code, r, n);
    }
    verifier(bons == (int)(sizeof cas / sizeof cas[0]),
             "les dispositions du signalfd_siginfo (kill, minuteur, poll, faute, MCE, SIGCHLD, temps reel, SIGSYS)");
    close(fd);
    masque(SIG_SETMASK, &ancien, NULL, 8);
}

/* Les minuteurs, lus par signalfd : un minuteur POSIX (SI_TIMER, son
 * numéro, ses dépassements, sa valeur) ; l'alarme périodique de
 * setitimer, réarmée quand son SIGALRM est pris (deux lectures
 * bloquantes). */
static void signalfd_minuteurs(void)
{
    int rt = SIGRTMIN + 2;
    uint64_t m = BIT(rt) | BIT(SIGALRM), ancien;
    masque(SIG_BLOCK, &m, &ancien, 8);
    int fd = (int)sfd4(-1, &m, 8, 0);
    struct sigevent ev;
    memset(&ev, 0, sizeof ev);
    ev.sigev_notify = SIGEV_SIGNAL;
    ev.sigev_signo = rt;
    ev.sigev_value.sival_ptr = (void *)0x123456789aLL;
    int id = -1;
    syscall(SYS_timer_create, CLOCK_MONOTONIC, &ev, &id);
    struct itimerspec it = { { 0, 1000000 }, { 0, 1000000 } };
    syscall(SYS_timer_settime, id, 0, &it, NULL);
    dormir_ms(30);
    struct ssi s[2];
    long n = lire(fd, s, 128);
    syscall(SYS_timer_delete, id);
    verifier(n == 128 && s[0].signo == (uint32_t)rt && s[0].code == SI_TIMER && s[0].tid == (uint32_t)id && s[0].overrun > 0
                 && s[0].ptr == 0x123456789aULL && s[0].entier == 0x3456789a && s[0].pid == 0,
             "un minuteur POSIX : SI_TIMER, ssi_tid, ssi_overrun, ssi_ptr et ssi_int");
    struct itimerval iv = { { 0, 10000 }, { 0, 10000 } }, arret = { { 0, 0 }, { 0, 0 } };
    setitimer(ITIMER_REAL, &iv, NULL);
    long x = lire(fd, &s[0], 128), y = lire(fd, &s[1], 128);
    setitimer(ITIMER_REAL, &arret, NULL);
    siginfo_t si;
    struct timespec zero = { 0, 0 };
    attendre(BIT(SIGALRM), &si, &zero);
    verifier(x == 128 && y == 128 && s[0].signo == SIGALRM && s[1].signo == SIGALRM && s[0].code == SI_KERNEL,
             "l'alarme periodique : deux SIGALRM (SI_KERNEL), reamee quand le premier est lu");
    close(fd);
    masque(SIG_SETMASK, &ancien, NULL, 8);
}

/* Le signalfd et l'epoll d'un processus qui finit (« signaux transmettre
 * »), gardés par un autre (« signaux garder ») : l'epoll a inscrit son
 * élément dans la file des signaux du premier (`current->sighand`), qui
 * disparaît avec lui. Linux réveille alors cette file avec POLLFREE
 * (`signalfd_cleanup`) : l'élément devient prêt une fois, puis plus jamais
 * ; et le signalfd lit les signaux de qui le lit. « signaux relacher » dit
 * à « garder » que « transmettre » est fini et recueilli. */
static const char PRISE[] = "\0claude-os-signaux";

static socklen_t adresse(struct sockaddr_un *a)
{
    memset(a, 0, sizeof *a);
    a->sun_family = AF_UNIX;
    memcpy(a->sun_path, PRISE, sizeof PRISE - 1);
    return (socklen_t)(offsetof(struct sockaddr_un, sun_path) + sizeof PRISE - 1);
}

static int connecter(void)
{
    struct sockaddr_un a;
    socklen_t l = adresse(&a);
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    for (int i = 0; i < 3000 && connect(s, (struct sockaddr *)&a, l) != 0; i++)
        dormir_ms(10);
    return s;
}

static int garder(void)
{
    nom = "signaux garder";
    alarm(120);
    struct sockaddr_un a;
    socklen_t l = adresse(&a);
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    verifier(bind(s, (struct sockaddr *)&a, l) == 0 && listen(s, 2) == 0, "a l'ecoute");
    int c1 = accept(s, NULL, NULL);
    char octet;
    int fds[2] = { -1, -1 };
    union {
        struct cmsghdr c;
        char o[CMSG_SPACE(sizeof fds)];
    } controle;
    struct iovec iov = { &octet, 1 };
    struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = controle.o, .msg_controllen = sizeof controle.o };
    long n = recvmsg(c1, &msg, 0);
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    if (n == 1 && c && c->cmsg_type == SCM_RIGHTS && c->cmsg_len == CMSG_LEN(sizeof fds))
        memcpy(fds, CMSG_DATA(c), sizeof fds);
    int ep = fds[0], sf = fds[1];
    verifier(ep >= 0 && sf >= 0, "l'epoll et le signalfd recus");
    int c2 = accept(s, NULL, NULL);
    uint64_t usr1 = BIT(SIGUSR1);
    masque(SIG_BLOCK, &usr1, NULL, 8);
    struct epoll_event r;
    struct ssi x;
    kill(getpid(), SIGUSR1);
    int une = epoll_wait(ep, &r, 1, 0) == 1 && r.events == EPOLLIN;
    long lu = lire(sf, &x, sizeof x);
    int plus = epoll_wait(ep, &r, 1, 0) == 0;
    kill(getpid(), SIGUSR1);
    plus &= epoll_wait(ep, &r, 1, 0) == 0;
    verifier(une && plus, "l'epoll d'un processus fini : pret une fois (POLLFREE), puis plus jamais");
    verifier(lu == 128 && x.signo == SIGUSR1 && x.pid == (uint32_t)getpid() && lire(sf, &x, sizeof x) == 128,
             "le signalfd recu lit les signaux de qui le lit");
    /* Écrit avant de rendre la main à « relacher » (sa connexion fermée) :
     * nos lignes passent avant les siennes. */
    printf("[linux] signaux garder : toutes les verifications : %s\n", echecs ? "ECHEC" : "ok");
    fflush(stdout);
    close(ep);
    close(sf);
    close(c1);
    close(c2);
    close(s);
    return echecs != 0;
}

static int transmettre(void)
{
    nom = "signaux transmettre";
    uint64_t usr1 = BIT(SIGUSR1);
    int sf = (int)sfd4(-1, &usr1, 8, SFD_NONBLOCK), ep = epoll_create1(0);
    struct epoll_event e = { EPOLLIN, { .u64 = 1 } };
    epoll_ctl(ep, EPOLL_CTL_ADD, sf, &e);
    int s = connecter();
    int fds[2] = { ep, sf };
    union {
        struct cmsghdr c;
        char o[CMSG_SPACE(sizeof fds)];
    } controle;
    memset(&controle, 0, sizeof controle);
    char octet = 'x';
    struct iovec iov = { &octet, 1 };
    struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = controle.o, .msg_controllen = sizeof controle.o };
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof fds);
    memcpy(CMSG_DATA(c), fds, sizeof fds);
    verifier(sendmsg(s, &msg, 0) == 1, "l'epoll et son signalfd envoyes");
    printf("[linux] signaux transmettre : toutes les verifications : %s\n", echecs ? "ECHEC" : "ok");
    return echecs != 0;
}

static int relacher(void)
{
    nom = "signaux relacher";
    int s = connecter();
    char octet;
    /* « garder » ferme la connexion quand il a fini. */
    verifier(read(s, &octet, 1) == 0, "garder a fini");
    printf("[linux] signaux relacher : toutes les verifications : %s\n", echecs ? "ECHEC" : "ok");
    return echecs != 0;
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "garder") == 0)
        return garder();
    if (argc > 1 && strcmp(argv[1], "transmettre") == 0)
        return transmettre();
    if (argc > 1 && strcmp(argv[1], "relacher") == 0)
        return relacher();
    actions();
    masques();
    attente();
    envois();
    pile_de_secours();
    files();
    signalfd_creation();
    signalfd_lecture();
    signalfd_dispositions();
    signalfd_minuteurs();
    printf("[linux] signaux : toutes les verifications : %s\n", echecs ? "ECHEC" : "ok");
    return echecs != 0;
}
