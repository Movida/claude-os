# verifier-ordre.awk : compare le journal d'un démarrage (serial.log) aux
# lignes attendues d'une étape (attendu.txt), dans l'ordre. verifier.sh s'en
# sert pour les étapes dont attendu.txt commence par « # Dans l'ordre ».
#
#   LC_ALL=C awk -v etape=06k-terminal -f verifier-ordre.awk serial.log attendu.txt
#
# LC_ALL=C : des octets, pas des caractères (le journal peut avoir des
# octets qui ne sont pas de l'UTF-8, ceux du BIOS) ; « … » y fait trois
# octets, partout pareil.
#
# Pourquoi : chercher chaque ligne n'importe où (la première façon de
# verifier.sh) laisse passer une ligne satisfaite par un autre programme,
# plus loin, ou par un morceau trop court pour rien prouver (« [noyau] TSC :
# », la relecture globale de novembre 2026). Ici, chaque ligne attendue se
# trouve à la ligne du journal de la précédente, ou après ; et le fichier
# attendu donne les lignes entières, ce qui change remplacé par « … ».
#
# Le format d'attendu.txt :
#   - une ligne vide, ou qui commence par « # » : un commentaire ;
#   - « ~ » puis une espace en tête : une ligne qui peut venir n'importe où
#     (ce que disent les programmes lancés en arrière-plan, par `&`, ou une
#     tâche du noyau à part, à leur heure) ; elle ne fait pas avancer
#     l'ordre ;
#   - « … » (U+2026) dans une ligne : une partie qui change d'un démarrage
#     à l'autre (une durée, une fréquence, une adresse), n'importe quel
#     texte, sur la même ligne du journal.
# Une ligne attendue se cherche DANS une ligne du journal (chaque morceau
# entre deux « … », dans l'ordre), pas comme la ligne entière : deux
# programmes qui tournent ensemble (lancés par `&`) écrivent dans la même
# console, et l'un peut écrire une ligne entière au milieu d'une ligne que
# l'autre écrit en deux fois (vu en 6k : un guetteur de `surveillance` dans
# une ligne du lecteur WebAssembly).
#
# Deux lignes attendues de suite peuvent se trouver dans la même ligne du
# journal (une ligne coupée par un autre programme) ; deux lignes attendues
# IDENTIQUES, jamais : la seconde est cherchée après la première.
#
# Sortie : « OK » ou « ECHEC » par ligne, comme verifier.sh ; le code de
# sortie dit s'il y a eu un échec. Un échec dit aussi, quand la ligne existe
# mais trop tôt, où elle est. Un journal vide, ou un attendu.txt sans ligne,
# est un échec (un démarrage muet, un port série cassé, ne passe pas).

# Le journal, d'abord, reconnu par son nom (pas par FNR == NR, qui le
# confondrait avec le fichier suivant s'il était vide) : ses lignes, sans le
# retour chariot éventuel.
FILENAME == ARGV[1] {
    sub(/\r$/, "")
    journal[++n] = $0
    next
}

/^#/ || /^$/ { next }

{
    attendue = $0
    examinees++
    libre = substr(attendue, 1, 2) == "~ "
    if (libre)
        attendue = substr(attendue, 3)
    debut = libre ? 1 : (curseur ? curseur + (attendue == precedente) : 1)
    if (!libre)
        precedente = attendue
    trouvee = 0
    for (i = debut; i <= n; i++)
        if (correspond(journal[i], attendue)) {
            trouvee = i
            break
        }
    if (trouvee) {
        print "OK     " etape " : " attendue
        if (!libre)
            curseur = trouvee
        next
    }
    echec = 1
    for (i = 1; i < debut; i++)
        if (correspond(journal[i], attendue)) {
            print "ECHEC  " etape " : " attendue " (a la ligne " i " du journal, avant celle de la precedente, " curseur ")"
            next
        }
    print "ECHEC  " etape " : " attendue
}

END {
    if (n == 0) {
        print "ECHEC  " etape " : le journal du demarrage est vide"
        echec = 1
    } else if (examinees == 0) {
        print "ECHEC  " etape " : aucune ligne attendue"
        echec = 1
    }
    exit echec
}

# La ligne `s` du journal contient-elle la ligne attendue `motif` ? Ses
# morceaux entre deux « … » s'y suivent, dans l'ordre. index() et non une
# expression régulière : les lignes ont des crochets, des points et des
# parenthèses, qu'il faudrait échapper.
function correspond(s, motif,    morceaux, m, k, j, pos) {
    m = split(motif, morceaux, "…")
    pos = 1
    for (k = 1; k <= m; k++) {
        if (morceaux[k] == "")
            continue
        j = index(substr(s, pos), morceaux[k])
        if (!j)
            return 0
        pos += j - 1 + length(morceaux[k])
    }
    return 1
}
