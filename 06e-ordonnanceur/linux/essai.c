/*
 * libessai.so : une bibliothèque partagée à nous, que linux/dynamique.c
 * charge à l'exécution (dlopen). Installée dans /usr/local/lib, que liste
 * /etc/ld.so.conf : ld-linux la trouve par son cache, comme une
 * bibliothèque installée sur un vrai système.
 *
 * Elle a ce qui demande le plus à ld-linux, et donc au noyau derrière
 * lui : un constructeur et un destructeur (appelés par ld-linux à dlopen
 * et à dlclose), et une variable propre à chaque fil (__thread), dont la
 * place n'existe qu'une fois la bibliothèque chargée (le TLS dynamique,
 * servi par __tls_get_addr, dans un bloc que ld-linux alloue par malloc au
 * premier accès du fil : mesuré, sur l'hôte, sans appel système).
 */

/* Mis à 1 par le constructeur. */
int essai_construite = 0;

/* Une variable par fil, à sa valeur initiale (le .tdata de la
 * bibliothèque, que ld-linux recopie pour chaque fil). */
static __thread int essai_par_fil = 42;

/* Où le destructeur signalera qu'il est passé : une variable du
 * programme, qu'il donne avant dlclose. */
static int *essai_fin = 0;

__attribute__((constructor)) static void construire(void)
{
    essai_construite = 1;
}

__attribute__((destructor)) static void detruire(void)
{
    if (essai_fin)
        *essai_fin = 1;
}

/* La valeur de la variable du fil, puis l'incrémente. */
int essai_suivant(void)
{
    return essai_par_fil++;
}

void essai_signaler_la_fin(int *fin)
{
    essai_fin = fin;
}
