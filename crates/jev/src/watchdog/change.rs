//! What changed in the persistence inventory since the last scan. A new
//! background item is the moment software decides to stay — worth surfacing
//! even when no rule fires.

use serde::Serialize;

use super::PersistenceItem;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum Change {
    Added { source: String },
    Removed { source: String },
    /// Same registration, different program or arguments.
    ProgramChanged { source: String, before: String, after: String },
}

/// Changes between two inventories, keyed by the registering file.
pub fn diff(before: &[PersistenceItem], after: &[PersistenceItem]) -> Vec<Change> {
    let mut out = Vec::new();
    for a in after {
        match before.iter().find(|b| b.source == a.source) {
            None => out.push(Change::Added { source: a.source.clone() }),
            Some(b) if b.program != a.program || b.arguments != a.arguments => out.push(Change::ProgramChanged {
                source: a.source.clone(),
                before: command(b),
                after: command(a),
            }),
            Some(_) => {}
        }
    }
    for b in before {
        if !after.iter().any(|a| a.source == b.source) {
            out.push(Change::Removed { source: b.source.clone() });
        }
    }
    out
}

fn command(i: &PersistenceItem) -> String {
    if i.arguments.is_empty() {
        i.program.clone()
    } else {
        i.arguments.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::super::ItemKind;
    use super::*;

    fn item(source: &str, program: &str) -> PersistenceItem {
        PersistenceItem {
            kind: ItemKind::UserAgent,
            source: source.into(),
            label: None,
            program: program.into(),
            arguments: vec![],
            run_at_load: false,
            keep_alive: false,
            program_exists: true,
            signature: None,
        }
    }

    #[test]
    fn detects_added_removed_and_changed() {
        let before = [item("/a.plist", "/x"), item("/b.plist", "/y")];
        let after = [item("/a.plist", "/x2"), item("/c.plist", "/z")];
        assert_eq!(
            diff(&before, &after),
            [
                Change::ProgramChanged {
                    source: "/a.plist".into(),
                    before: "/x".into(),
                    after: "/x2".into()
                },
                Change::Added { source: "/c.plist".into() },
                Change::Removed { source: "/b.plist".into() },
            ]
        );
    }
}
