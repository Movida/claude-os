// Script de construction : exécuté par cargo avant de compiler le noyau.
// Son seul rôle : donner notre script d'édition de liens à l'éditeur de
// liens, avec un chemin absolu (cargo ne garantit pas le dossier courant).
fn main() {
    let dossier = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-arg=-T{dossier}/linker.ld");
    println!("cargo:rerun-if-changed=linker.ld");
}
