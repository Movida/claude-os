//! Le graphe des sockets AF_UNIX « en vol », et ce qu'il reste à ramasser
//! (net/unix/garbage.c, version de Linux 6.10 et après).
//!
//! LE PROBLÈME. SCM_RIGHTS met un fichier dans la file d'une socket : la file le tient. Une
//! socket envoyée dans sa propre file, ou deux qui se tiennent l'une l'autre, ne se ferment donc
//! jamais par les comptes de références : leur dernier `close` n'arrive jamais, puisque
//! c'est la file qui les tient, et que seule leur fermeture jetterait la file. Rien ne peut plus
//! les lire : il n'y a plus de descripteur. Il faut les trouver, et jeter leurs files.
//!
//! LE GRAPHE. Un sommet par socket en vol. Une arête par exemplaire de fichier en vol : de la
//! socket envoyée à celle dont la file la tient (`unix_edge`). Une socket n'est utile que si l'on
//! peut la lire, et elle ne peut être lue que par un descripteur, ou une fois sortie de la file qui
//! la tient. Donc : une composante fortement connexe est morte si plus rien ne la tient
//! de l'extérieur : aucun de ses fichiers n'a d'autre référence que ses exemplaires en vol
//! (`unix_vertex_dead`), et tous sont dans des files de cette même composante.
//!
//! Une composante sans cycle n'a pas besoin de nous : quand la file qui la tient sera jetée, ses
//! références tomberont. Elle ne vérifie jamais le test : son unique sommet aurait une arête vers
//! lui-même, ou vers une autre composante.
//!
//! LA FILLE PAS ENCORE ACCEPTÉE d'une écoute (`ecoute`) n'a pas de fichier : c'est l'écoute qui
//! la tient, donc ce qu'elle a en file (`unix_edge_successor`). Une arête vers elle compte comme
//! une arête vers l'écoute.
//!
//! Choix de conception : tout recalculer à chaque ramassage, depuis la liste des arêtes. Linux garde
//! ses sommets et ses composantes d'une fois sur l'autre (`unix_graph_grouped`), pour ne rien
//! parcourir quand le graphe n'a pas changé : un ramassage suit chaque fermeture d'une socket
//! AF_UNIX tant qu'il en reste en vol, sur des machines où il y en a des milliers. Ici, quelques
//! dizaines ; et une structure de moins à tenir juste. Le parcours est celui de Tarjan, sans
//! récursion : la pile du noyau ne fait que 16 Kio, et le graphe est écrit par les programmes.
//!
//! Un écart, voulu : Linux compare l'indice de composante de deux sommets (`scc_index`), lequel n'est
//! que le « lowlink » de Tarjan : il peut différer entre deux sommets d'une même composante
//! (r → a → b → a, a → r : b garde l'indice de a). La composante passe alors pour vivante, et reste
//! là. Nous numérotons les composantes : celle-là est ramassée.

use alloc::collections::TryReserveError;
use alloc::vec::Vec;

/// Un exemplaire d'une socket en vol (`unix_edge`).
#[derive(Clone, Copy, Debug)]
pub struct Arete {
    /// Le message qui le porte (pour le retirer d'un coup, à sa lecture).
    pub message: u64,
    /// La socket envoyée, et le numéro de son fichier.
    pub envolee: u64,
    pub fichier: u32,
    /// La socket dont la file tient le message ; si c'est une fille pas encore acceptée, son écoute.
    pub receveuse: u64,
    pub ecoute: Option<u64>,
}

/// Pas de lien : la receveuse n'est pas en vol.
const DEHORS: u32 = u32::MAX;
const PAS_VU: u32 = u32::MAX;

#[derive(Clone, Copy)]
struct Sommet {
    numero: u64,
    fichier: u32,
    /// Ses liens, à partir de `premier`, dans `liens`.
    premier: u32,
    degre: u32,
    /// L'ordre de sa découverte, le plus petit qu'il atteint (`index` et `lowlink`).
    index: u32,
    bas: u32,
    sur_pile: bool,
    composante: u32,
}

/// Les sockets dont il faut jeter la file : celles des composantes mortes, selon `references`, le
/// compte des références d'un fichier. L'appelant tient ce qui empêche le graphe et ces comptes
/// de changer pendant l'appel.
pub fn mortes(aretes: &[Arete], references: impl Fn(u32) -> u32) -> Result<Vec<u64>, TryReserveError> {
    let mut sommets: Vec<Sommet> = Vec::new();
    sommets.try_reserve_exact(aretes.len())?;
    for a in aretes {
        sommets.push(Sommet { numero: a.envolee, fichier: a.fichier, premier: 0, degre: 0, index: PAS_VU, bas: 0, sur_pile: false, composante: 0 });
    }
    sommets.sort_unstable_by_key(|s| s.numero);
    sommets.dedup_by_key(|s| s.numero);
    let indice = |n: u64| sommets.binary_search_by_key(&n, |s| s.numero).map_or(DEHORS, |i| i as u32);
    // Les liens de chaque sommet, à la suite.
    let mut liens: Vec<(u32, u32)> = Vec::new();
    liens.try_reserve_exact(aretes.len())?;
    for a in aretes {
        liens.push((indice(a.envolee), indice(a.ecoute.unwrap_or(a.receveuse))));
    }
    liens.sort_unstable();
    for (k, &(source, _)) in liens.iter().enumerate() {
        let s = &mut sommets[source as usize];
        if s.degre == 0 {
            s.premier = k as u32;
        }
        s.degre += 1;
    }
    // Tarjan : `appels` tient la récursion, un sommet et le rang du lien suivant ; `pile`, les
    // sommets dont la composante n'est pas encore finie.
    let n = sommets.len();
    let mut appels: Vec<(u32, u32)> = Vec::new();
    appels.try_reserve_exact(n)?;
    let mut pile: Vec<u32> = Vec::new();
    pile.try_reserve_exact(n)?;
    let mut mortes = Vec::new();
    let (mut ordre, mut composantes) = (0, 0);
    for depart in 0..n as u32 {
        if sommets[depart as usize].index != PAS_VU {
            continue;
        }
        appels.push((depart, 0));
        while let Some(&(v, rang)) = appels.last() {
            let vi = v as usize;
            if rang == 0 {
                sommets[vi].index = ordre;
                sommets[vi].bas = ordre;
                sommets[vi].sur_pile = true;
                ordre += 1;
                pile.push(v);
            }
            if rang < sommets[vi].degre {
                if let Some(a) = appels.last_mut() {
                    a.1 += 1;
                }
                let cible = liens[(sommets[vi].premier + rang) as usize].1;
                if cible == DEHORS {
                    continue;
                }
                let c = sommets[cible as usize];
                if c.index == PAS_VU {
                    // `appels` ne porte chaque sommet qu'une fois : sa place est réservée.
                    appels.push((cible, 0));
                } else if c.sur_pile {
                    sommets[vi].bas = sommets[vi].bas.min(c.index);
                }
                continue;
            }
            // Ses liens sont vus : il rend ce qu'il atteint à qui l'a appelé.
            appels.pop();
            if let Some(&(parent, _)) = appels.last() {
                let bas = sommets[vi].bas;
                let p = &mut sommets[parent as usize];
                p.bas = p.bas.min(bas);
            }
            if sommets[vi].bas != sommets[vi].index {
                continue;
            }
            // Une composante est finie : ses sommets sont en haut de la pile, jusqu'à lui.
            composantes += 1;
            let debut = pile.iter().rposition(|&x| x == v).unwrap_or(0);
            for &m in &pile[debut..] {
                sommets[m as usize].sur_pile = false;
                sommets[m as usize].composante = composantes;
            }
            let morte = pile[debut..].iter().all(|&m| {
                let s = &sommets[m as usize];
                references(s.fichier) == s.degre
                    && liens[s.premier as usize..(s.premier + s.degre) as usize]
                        .iter()
                        .all(|&(_, c)| c != DEHORS && sommets[c as usize].composante == composantes)
            });
            if morte {
                mortes.try_reserve(pile.len() - debut)?;
                mortes.extend(pile[debut..].iter().map(|&m| sommets[m as usize].numero));
            }
            pile.truncate(debut);
        }
    }
    Ok(mortes)
}
