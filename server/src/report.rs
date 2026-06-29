use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Safe,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Safe => "SAFE",
        };
        write!(f, "{}", s)
    }
}

#[derive(Serialize, Clone)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
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
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub risk_score: Severity,
}

pub fn summarize(findings: &[Finding]) -> Summary {
    let critical = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high = findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let medium = findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count();
    let low = findings
        .iter()
        .filter(|f| f.severity == Severity::Low)
        .count();

    let risk_score = match (critical, high) {
        (c, _) if c > 0 => Severity::Critical,
        (_, d) if d > 0 => Severity::High,
        _ if medium > 0 => Severity::Medium,
        _ if low > 0 => Severity::Low,
        _ => Severity::Safe,
    };

    Summary {
        total_findings: findings.len(),
        critical,
        high,
        medium,
        low,
        risk_score,
    }
}

pub fn generate_audit_id(contract_hash: &str, findings: &[Finding]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(contract_hash.as_bytes());
    for f in findings {
        hasher.update(f.id.as_bytes());
        hasher.update(f.severity.to_string().as_bytes());
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
        assert_eq!(summary.critical, 0);
        assert_eq!(summary.high, 0);
        assert_eq!(summary.medium, 0);
        assert_eq!(summary.low, 0);
        assert_eq!(summary.risk_score, Severity::Safe);
    }

    #[test]
    fn test_summarize_critical() {
        let findings = vec![
            Finding {
                id: "1".to_string(),
                severity: Severity::Critical,
                title: "Crit".to_string(),
                description: "Crit".to_string(),
                line: 1,
                pattern: "pat".to_string(),
                ai_explanation: None,
            },
            Finding {
                id: "2".to_string(),
                severity: Severity::Low,
                title: "Low".to_string(),
                description: "Low".to_string(),
                line: 2,
                pattern: "pat".to_string(),
                ai_explanation: None,
            },
        ];
        let summary = summarize(&findings);
        assert_eq!(summary.total_findings, 2);
        assert_eq!(summary.critical, 1);
        assert_eq!(summary.low, 1);
        assert_eq!(summary.risk_score, Severity::Critical);
    }

    #[test]
    fn test_summarize_high() {
        let findings = vec![Finding {
            id: "1".to_string(),
            severity: Severity::High,
            title: "High".to_string(),
            description: "High".to_string(),
            line: 1,
            pattern: "pat".to_string(),
            ai_explanation: None,
        }];
        let summary = summarize(&findings);
        assert_eq!(summary.risk_score, Severity::High);
    }

    #[test]
    fn test_summarize_medium() {
        let findings = vec![Finding {
            id: "1".to_string(),
            severity: Severity::Medium,
            title: "Med".to_string(),
            description: "Med".to_string(),
            line: 1,
            pattern: "pat".to_string(),
            ai_explanation: None,
        }];
        let summary = summarize(&findings);
        assert_eq!(summary.risk_score, Severity::Medium);
    }

    #[test]
    fn test_generate_audit_id() {
        let findings = vec![Finding {
            id: "S402-001".to_string(),
            severity: Severity::High,
            title: "Title".to_string(),
            description: "Desc".to_string(),
            line: 1,
            pattern: "pat".to_string(),
            ai_explanation: None,
        }];
        let id1 = generate_audit_id("hash1", &findings);
        let id2 = generate_audit_id("hash2", &findings);
        assert_ne!(id1, id2, "Audit ID should be unique to the contract hash");
        assert!(id1.starts_with("audit-"));
    }
}
