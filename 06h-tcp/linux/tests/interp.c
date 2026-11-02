/*
 * Un programme dynamique qui ne doit jamais tourner : le Makefile le lie
 * avec un interpréteur (PT_INTERP) faux, absent ou interdit, que le noyau
 * doit refuser avec l'errno de Linux (voir tests-attendu.txt).
 */
int main(void)
{
    return 1;
}
