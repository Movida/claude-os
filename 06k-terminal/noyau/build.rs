// Script de construction : exécuté par cargo avant de compiler le noyau.
// Ses deux rôles : donner notre script d'édition de liens à l'éditeur de
// liens, avec un chemin absolu (cargo ne garantit pas le dossier courant) ;
// nommer le compilateur, pour /proc/version (procfs.rs).
fn main() {
    let dossier = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-arg=-T{dossier}/linker.ld");
    println!("cargo:rerun-if-changed=linker.ld");
    // Le LINUX_COMPILER de Linux, que son Makefile tire de `$(CC) -v` à
    // chaque construction : ici la ligne de `rustc --version` (le
    // compilateur que cargo nous donne dans RUSTC, celui de
    // rust-toolchain.toml), dans la variable COMPILATEUR que lit le noyau
    // (`env!`). Linux y ajoute son éditeur de liens ; le nôtre, rust-lld,
    // vient avec rustc, à la même version : le nom de rustc le dit. Un
    // changement de compilateur reconstruit tout, ce script compris.
    let rustc = std::env::var("RUSTC").unwrap();
    let sortie = std::process::Command::new(rustc).arg("--version").output().unwrap();
    let version = String::from_utf8(sortie.stdout).unwrap();
    println!("cargo:rustc-env=COMPILATEUR={}", version.trim());
}
