use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Serialize, Clone)]
pub struct Finding {
    pub id: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub line: usize,
    pub pattern: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_explanation: Option<String>,
}

#[derive(Serialize)]
pub struct Summary {
    pub total_findings: usize,
    pub catastrophe: usize,
    pub disaster: usize,
    pub calamity: usize,
    pub hazard: usize,
    pub risk_score: String,
}

pub fn summarize(findings: &[Finding]) -> Summary {
    let catastrophe = findings.iter().filter(|f| f.severity == "CATASTROPHE").count();
    let disaster = findings.iter().filter(|f| f.severity == "DISASTER").count();
    let calamity = findings.iter().filter(|f| f.severity == "CALAMITY").count();
    let hazard = findings.iter().filter(|f| f.severity == "HAZARD").count();

    let risk_score = match (catastrophe, disaster) {
        (c, _) if c > 0 => "CATASTROPHE",
        (_, d) if d > 0 => "DISASTER",
        _ if calamity > 0 => "CALAMITY",
        _ if hazard > 0 => "HAZARD",
        _ => "SAFE",
    };

    Summary {
        total_findings: findings.len(),
        catastrophe,
        disaster,
        calamity,
        hazard,
        risk_score: risk_score.to_string(),
    }
}

pub fn generate_audit_id(contract_hash: &str, findings: &[Finding]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(contract_hash.as_bytes());
    for f in findings {
        hasher.update(f.id.as_bytes());
        hasher.update(f.severity.as_bytes());
    }
    let result = hasher.finalize();
    format!("audit-{}", hex::encode(&result[..8]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_summarize_empty() {
        let summary = summarize(&[]);
        assert_eq!(summary.total_findings, 0);
        assert_eq!(summary.catastrophe, 0);
        assert_eq!(summary.disaster, 0);
        assert_eq!(summary.calamity, 0);
        assert_eq!(summary.hazard, 0);
        assert_eq!(summary.risk_score, "SAFE");
    }

    #[test]
    fn test_summarize_critical() {
        let findings = vec![
            Finding {
                id: "1".to_string(),
                severity: "CATASTROPHE".to_string(),
                title: "Crit".to_string(),
                description: "Crit".to_string(),
                line: 1,
                pattern: "pat".to_string(),
                ai_explanation: None,
            },
            Finding {
                id: "2".to_string(),
                severity: "HAZARD".to_string(),
                title: "Low".to_string(),
                description: "Low".to_string(),
                line: 2,
                pattern: "pat".to_string(),
                ai_explanation: None,
            },
        ];
        let summary = summarize(&findings);
        assert_eq!(summary.total_findings, 2);
        assert_eq!(summary.catastrophe, 1);
        assert_eq!(summary.hazard, 1);
        assert_eq!(summary.risk_score, "CATASTROPHE");
    }

    #[test]
    fn test_summarize_high() {
        let findings = vec![
            Finding {
                id: "1".to_string(),
                severity: "DISASTER".to_string(),
                title: "High".to_string(),
                description: "High".to_string(),
                line: 1,
                pattern: "pat".to_string(),
                ai_explanation: None,
            },
        ];
        let summary = summarize(&findings);
        assert_eq!(summary.risk_score, "DISASTER");
    }

    #[test]
    fn test_summarize_medium() {
        let findings = vec![
            Finding {
                id: "1".to_string(),
                severity: "CALAMITY".to_string(),
                title: "Med".to_string(),
                description: "Med".to_string(),
                line: 1,
                pattern: "pat".to_string(),
                ai_explanation: None,
            },
        ];
        let summary = summarize(&findings);
        assert_eq!(summary.risk_score, "CALAMITY");
    }

    #[test]
    fn test_generate_audit_id() {
        let findings = vec![
            Finding {
                id: "S402-001".to_string(),
                severity: "DISASTER".to_string(),
                title: "Title".to_string(),
                description: "Desc".to_string(),
                line: 1,
                pattern: "pat".to_string(),
                ai_explanation: None,
            },
        ];
        let id1 = generate_audit_id("hash1", &findings);
        let id2 = generate_audit_id("hash2", &findings);
        assert_ne!(id1, id2, "Audit ID should be unique to the contract hash");
        assert!(id1.starts_with("audit-"));
    }
}
