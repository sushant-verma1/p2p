//! `architecture.md` §2: dependencies flow strictly downward. Declared here so
//! that an upward or lateral edge fails the build rather than a code review.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

/// What each workspace member is allowed to depend on, internally.
///
/// The binary is the only thing that may name `p2pchat-tui`: something has to
/// run the terminal, and the rule in §2 is about the library layering.
const ALLOWED: &[(&str, &[&str])] = &[
    ("p2pchat-core", &[]),
    ("p2pchat-crypto", &["p2pchat-core"]),
    ("p2pchat-store", &["p2pchat-core"]),
    ("p2pchat-net", &["p2pchat-core", "p2pchat-crypto"]),
    ("p2pchat-tui", &["p2pchat-core"]),
    (
        "p2pchat",
        &[
            "p2pchat-core",
            "p2pchat-crypto",
            "p2pchat-net",
            "p2pchat-store",
            "p2pchat-tui",
        ],
    ),
];

fn crates_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Internal dependencies of one member, from every dependency table.
fn internal_deps(manifest: &toml::Value) -> BTreeSet<String> {
    ["dependencies", "dev-dependencies", "build-dependencies"]
        .iter()
        .filter_map(|table| manifest.get(table)?.as_table())
        .flat_map(|table| table.keys().cloned())
        .filter(|name| name.starts_with("p2pchat"))
        .collect()
}

#[test]
fn dependencies_flow_downward() {
    let allowed: BTreeMap<_, _> = ALLOWED
        .iter()
        .map(|(krate, deps)| (*krate, deps.iter().copied().collect::<BTreeSet<_>>()))
        .collect();

    let mut seen = BTreeSet::new();
    for entry in std::fs::read_dir(crates_dir()).unwrap() {
        let path = entry.unwrap().path().join("Cargo.toml");
        let manifest: toml::Value = std::fs::read_to_string(&path).unwrap().parse().unwrap();
        let name = manifest["package"]["name"].as_str().unwrap().to_owned();

        let permitted = allowed
            .get(name.as_str())
            .unwrap_or_else(|| panic!("{name} is not listed in ALLOWED"));

        for dep in internal_deps(&manifest) {
            assert!(
                permitted.contains(dep.as_str()),
                "{name} may not depend on {dep} (architecture.md §2)"
            );
        }
        seen.insert(name);
    }

    let expected: BTreeSet<_> = ALLOWED.iter().map(|(k, _)| k.to_string()).collect();
    assert_eq!(seen, expected, "workspace members changed");
}
