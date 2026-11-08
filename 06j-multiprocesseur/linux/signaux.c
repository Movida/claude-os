/*
 * Les signaux enregistrés (6d) : rt_sigaction, rt_sigprocmask,
 * rt_sigpending, sigaltstack, kill, tkill, tgkill ; puis leur file et leur
 * siginfo (6f) : rt_sigqueueinfo, rt_tgsigqueueinfo, rt_sigtimedwait, et
 * RLIMIT_SIGPENDING. Il tourne dans notre noyau et sur l'hôte (make
 * tests-hote) : chaque ligne doit dire « ok » des deux côtés. Rien ici
 * n'appelle de gestionnaire (gestionnaires.c le fait) : les signaux envoyés
 * sont ignorés, ou bloqués puis effacés, ou pris par rt_sigtimedwait.
 *
 * Les appels passent par syscall() quand la glibc changerait ce qu'on
 * veut voir : son sigaction() traduit sa propre structure et ajoute
 * SA_RESTORER ; ici, on parle au noyau avec la sienne.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <time.h>
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

int main(void)
{
    actions();
    masques();
    attente();
    envois();
    pile_de_secours();
    files();
    printf("[linux] signaux : toutes les verifications : %s\n", echecs ? "ECHEC" : "ok");
    return echecs != 0;
}
