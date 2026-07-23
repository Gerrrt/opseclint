//! Optional enrichment from a real SigmaHQ ruleset.
//!
//! Point opseclint at a checkout of <https://github.com/SigmaHQ/sigma> (or any
//! directory of Sigma-format YAML) with `--sigma <DIR>`. We index every rule by
//! the ATT&CK technique(s) in its `tags`, then attach the genuine rule
//! title/UUID/level to any finding whose technique matches — replacing the
//! seed KB's representative detection references with real, linkable rules.
//!
//! The ruleset is read at runtime and never bundled, so the binary stays
//! self-contained and no detection-rule licensing is redistributed.

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

use crate::model::{Detection, Report};

/// Maximum real Sigma rules to attach per finding, to keep output readable.
const MAX_RULES_PER_FINDING: usize = 5;

#[derive(Debug, Deserialize)]
struct LogSource {
    product: Option<String>,
}

/// The subset of a Sigma rule we care about.
#[derive(Debug, Deserialize)]
struct SigmaRuleRaw {
    title: Option<String>,
    id: Option<String>,
    level: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    logsource: Option<LogSource>,
}

/// A resolved Sigma rule reference.
#[derive(Debug, Clone)]
pub struct SigmaRule {
    pub id: String,
    pub title: String,
    pub level: String,
}

/// Technique-id -> matching Sigma rules.
#[derive(Debug, Default)]
pub struct SigmaIndex {
    by_technique: HashMap<String, Vec<SigmaRule>>,
    pub files_scanned: usize,
    pub rules_indexed: usize,
}

fn level_rank(level: &str) -> u8 {
    match level.to_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

/// Turn a Sigma tag like `attack.t1003.008` into a technique id `T1003.008`.
/// Returns `None` for non-technique tags (tactics, groups, software, etc.).
fn technique_from_tag(tag: &str) -> Option<String> {
    let rest = tag.strip_prefix("attack.")?;
    // Must look like t<digits>[.<digits>].
    if !rest.chars().next()?.eq_ignore_ascii_case(&'t') {
        return None;
    }
    let body = &rest[1..];
    if body.is_empty() || !body.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return None;
    }
    Some(format!("T{body}"))
}

impl SigmaIndex {
    /// Recursively load every `.yml`/`.yaml` Sigma rule under `dir`. Rules whose
    /// logsource product is set to something other than `linux` are skipped, to
    /// keep matches relevant to this platform. Unparseable files are ignored.
    pub fn load_dir(dir: &Path) -> std::io::Result<SigmaIndex> {
        let mut index = SigmaIndex::default();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(path) = stack.pop() {
            for entry in std::fs::read_dir(&path)? {
                let entry = entry?;
                let p = entry.path();
                if p.is_dir() {
                    stack.push(p);
                    continue;
                }
                let is_yaml = matches!(
                    p.extension().and_then(|e| e.to_str()),
                    Some("yml") | Some("yaml")
                );
                if !is_yaml {
                    continue;
                }
                index.files_scanned += 1;
                if let Ok(content) = std::fs::read_to_string(&p) {
                    index.ingest_file(&content);
                }
            }
        }
        Ok(index)
    }

    fn ingest_file(&mut self, content: &str) {
        // A Sigma file may hold multiple YAML documents.
        for doc in serde_yaml::Deserializer::from_str(content) {
            let Ok(raw) = SigmaRuleRaw::deserialize(doc) else {
                continue;
            };
            // Keep Linux-relevant rules (product linux or unspecified).
            if let Some(ls) = &raw.logsource
                && let Some(product) = &ls.product
                && product.to_lowercase() != "linux"
            {
                continue;
            }
            let (Some(id), Some(title)) = (raw.id, raw.title) else {
                continue;
            };
            let level = raw.level.unwrap_or_else(|| "medium".to_string());
            let mut indexed_any = false;
            for tag in &raw.tags {
                if let Some(tech) = technique_from_tag(tag) {
                    self.by_technique.entry(tech).or_default().push(SigmaRule {
                        id: id.clone(),
                        title: title.clone(),
                        level: level.clone(),
                    });
                    indexed_any = true;
                }
            }
            if indexed_any {
                self.rules_indexed += 1;
            }
        }
    }

    /// All Sigma rules matching any of the given technique ids, deduplicated by
    /// rule id, ranked by severity then title, capped for readability.
    pub fn rules_for(&self, technique_ids: &[String]) -> Vec<SigmaRule> {
        let mut out: Vec<SigmaRule> = Vec::new();
        for tid in technique_ids {
            if let Some(rules) = self.by_technique.get(tid) {
                for r in rules {
                    if !out.iter().any(|e| e.id == r.id) {
                        out.push(r.clone());
                    }
                }
            }
        }
        out.sort_by(|a, b| {
            level_rank(&b.level)
                .cmp(&level_rank(&a.level))
                .then(a.title.cmp(&b.title))
        });
        out.truncate(MAX_RULES_PER_FINDING);
        out
    }
}

/// Replace each finding's representative detections with real Sigma rules where
/// the technique matches. Findings with no match keep their seed detections.
/// Returns the number of findings that were enriched.
pub fn enrich(report: &mut Report, index: &SigmaIndex) -> usize {
    let mut enriched = 0;
    for f in &mut report.findings {
        let tids: Vec<String> = f.techniques.iter().map(|t| t.id.clone()).collect();
        let rules = index.rules_for(&tids);
        if rules.is_empty() {
            continue;
        }
        f.detections = rules
            .into_iter()
            .map(|r| Detection {
                source: "Sigma".to_string(),
                rule: format!("{} ({})", r.title, r.id),
                confidence: r.level,
            })
            .collect();
        enriched += 1;
    }
    enriched
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{analyzer, kb};
    use std::path::PathBuf;

    fn fixtures() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sigma")
    }

    #[test]
    fn technique_tag_parsing() {
        assert_eq!(
            technique_from_tag("attack.t1003.008").as_deref(),
            Some("T1003.008")
        );
        assert_eq!(technique_from_tag("attack.t1059").as_deref(), Some("T1059"));
        assert_eq!(technique_from_tag("attack.credential_access"), None);
        assert_eq!(technique_from_tag("attack.g0016"), None);
    }

    #[test]
    fn indexes_and_enriches_from_fixtures() {
        let index = SigmaIndex::load_dir(&fixtures()).expect("fixtures load");
        assert!(index.rules_indexed >= 2, "expected fixture rules indexed");

        let kb = kb::load().unwrap();
        let mut report = analyzer::analyze("cat /etc/shadow", &kb);
        let n = enrich(&mut report, &index);
        assert!(n >= 1);

        let shadow = report
            .findings
            .iter()
            .find(|f| f.rule_id == "shadow-read")
            .unwrap();
        // The seed reference is replaced by the real fixture rule + its UUID.
        assert!(
            shadow
                .detections
                .iter()
                .any(|d| d.rule.contains("11111111-1111-1111-1111-111111111111"))
        );
    }

    #[test]
    fn non_linux_rules_are_skipped() {
        let index = SigmaIndex::load_dir(&fixtures()).expect("fixtures load");
        // The Windows fixture is tagged T1057 but must not be indexed.
        assert!(index.rules_for(&["T1057".to_string()]).is_empty());
    }
}
