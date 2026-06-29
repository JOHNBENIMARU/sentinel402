use crate::ast::{FieldInfo, FnInfo};
use crate::engine::Detector;
use crate::report::{Finding, Severity};
use tree_sitter::Tree;

pub struct Cep18ComplianceDetector;

impl Detector for Cep18ComplianceDetector {
    fn analyze(
        &self,
        _tree: &Tree,
        _source: &str,
        functions: &[FnInfo],
        _fields: &[FieldInfo],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        let has_transfer = functions.iter().any(|f| f.name == "transfer");
        let has_approve = functions.iter().any(|f| f.name == "approve");

        if has_transfer && !has_approve {
            findings.push(Finding {
                id: format!("S402-C18-{:03}", findings.len() + 1),
                severity: Severity::Low,
                title: "CEP-18 Non-compliance: Missing approve".to_string(),
                description:
                    "Contract implements transfer() but is missing approve(). Fails CEP-18 standard compliance."
                        .to_string(),
                line: 0,
                pattern: "cep18_compliance".to_string(),
                ai_explanation: None,
            });
        }
        
        findings
    }
}
