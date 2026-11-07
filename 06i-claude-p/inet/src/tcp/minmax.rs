//! Le plus petit RTT récent : le filtre de Kathleen Nichols tel que l'écrit
//! Linux (lib/win_minmax.c). Garder le minimum d'une fenêtre glissante demande
//! d'ordinaire toutes ses valeurs ; trois suffisent à l'estimer : le meilleur,
//! le meilleur du dernier trois quarts, celui de la dernière moitié. Quand le
//! premier sort de la fenêtre, le deuxième prend sa place. RACK et HyStart s'en
//! servent : le RTT sans file d'attente.

#[derive(Debug, Clone, Copy, Default)]
struct Echantillon {
    t: u64,
    v: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct MinMax {
    s: [Echantillon; 3],
    /// Aucune mesure encore : le minimum vaut l'infini (`~0U`).
    pose: bool,
}

impl MinMax {
    pub const fn new() -> MinMax {
        MinMax { s: [Echantillon { t: 0, v: 0 }; 3], pose: false }
    }

    /// Le minimum de la fenêtre.
    pub fn valeur(&self) -> u64 {
        if self.pose { self.s[0].v } else { u64::MAX }
    }

    /// Une mesure `v` à l'heure `t`, dans une fenêtre de `fenetre`
    /// (`minmax_running_min`).
    pub fn mesure(&mut self, fenetre: u64, t: u64, v: u64) {
        let val = Echantillon { t, v };
        if !self.pose || v <= self.s[0].v || t.saturating_sub(self.s[2].t) > fenetre {
            self.s = [val; 3];
            self.pose = true;
            return;
        }
        if v <= self.s[1].v {
            self.s[2] = val;
            self.s[1] = val;
        } else if v <= self.s[2].v {
            self.s[2] = val;
        }
        // `minmax_subwin_update`.
        let dt = t.saturating_sub(self.s[0].t);
        if dt > fenetre {
            self.s[0] = self.s[1];
            self.s[1] = self.s[2];
            self.s[2] = val;
            if t.saturating_sub(self.s[0].t) > fenetre {
                self.s[0] = self.s[1];
                self.s[1] = self.s[2];
                self.s[2] = val;
            }
        } else if self.s[1].t == self.s[0].t && dt > fenetre / 4 {
            self.s[2] = val;
            self.s[1] = val;
        } else if self.s[2].t == self.s[1].t && dt > fenetre / 2 {
            self.s[2] = val;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn le_minimum_d_une_fenetre_qui_glisse() {
        let mut m = MinMax::new();
        assert_eq!(m.valeur(), u64::MAX);
        m.mesure(100, 0, 50);
        m.mesure(100, 10, 70);
        assert_eq!(m.valeur(), 50);
        // Un quart de fenêtre passé : 80 devient le deuxième choix.
        m.mesure(100, 30, 80);
        // La moitié : 90, le troisième.
        m.mesure(100, 60, 90);
        assert_eq!(m.valeur(), 50);
        // 50 sort de la fenêtre : 80 prend sa place.
        m.mesure(100, 110, 95);
        assert_eq!(m.valeur(), 80);
        // Une mesure plus petite efface tout.
        m.mesure(100, 111, 10);
        assert_eq!(m.valeur(), 10);
    }

    /// lib/win_minmax.c, recopié du C, ligne à ligne : la référence.
    struct Reference {
        s: [(u32, u32); 3],
    }

    impl Reference {
        fn subwin(&mut self, win: u32, val: (u32, u32)) {
            let dt = val.0.wrapping_sub(self.s[0].0);
            if dt > win {
                self.s[0] = self.s[1];
                self.s[1] = self.s[2];
                self.s[2] = val;
                if val.0.wrapping_sub(self.s[0].0) > win {
                    self.s[0] = self.s[1];
                    self.s[1] = self.s[2];
                    self.s[2] = val;
                }
            } else if self.s[1].0 == self.s[0].0 && dt > win / 4 {
                self.s[2] = val;
                self.s[1] = val;
            } else if self.s[2].0 == self.s[1].0 && dt > win / 2 {
                self.s[2] = val;
            }
        }

        fn running_min(&mut self, win: u32, t: u32, meas: u32) -> u32 {
            let val = (t, meas);
            if val.1 <= self.s[0].1 || val.0.wrapping_sub(self.s[2].0) > win {
                self.s = [val; 3];
                return meas;
            }
            if val.1 <= self.s[1].1 {
                self.s[2] = val;
                self.s[1] = val;
            } else if val.1 <= self.s[2].1 {
                self.s[2] = val;
            }
            self.subwin(win, val);
            self.s[0].1
        }
    }

    /// Des mesures au hasard, et de petites fenêtres : ses trois échantillons suivent ceux de Linux.
    #[test]
    fn comme_le_c_de_linux() {
        for graine in 1..=40u64 {
            let mut x = graine.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
            let mut hasard = move |m: u64| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x % m
            };
            let fenetre = 20 + hasard(200) as u32;
            let mut t = 1u32;
            let mut r = Reference { s: [(t, 1000); 3] };
            let mut m = MinMax::new();
            m.mesure(fenetre as u64, t as u64, 1000);
            for _ in 0..2000 {
                t += hasard((fenetre / 3) as u64) as u32;
                let v = 900 + hasard(200) as u32;
                let attendu = r.running_min(fenetre, t, v);
                m.mesure(fenetre as u64, t as u64, v as u64);
                assert_eq!(m.valeur(), attendu as u64);
                for k in 0..3 {
                    assert_eq!((m.s[k].t, m.s[k].v), (r.s[k].0 as u64, r.s[k].1 as u64), "{k}");
                }
            }
        }
    }

    /// Tout juste la fenêtre écoulée : la plus vieille mesure vaut encore ; un de plus, non.
    #[test]
    fn la_fenetre_tout_juste() {
        let mut m = MinMax::new();
        m.mesure(100, 1000, 5);
        m.mesure(100, 1100, 9);
        assert_eq!(m.valeur(), 5);
        let mut m = MinMax::new();
        m.mesure(100, 1000, 5);
        m.mesure(100, 1101, 9);
        assert_eq!(m.valeur(), 9);
    }
}
