use crate::ast::{self, FieldInfo, FnInfo};
use crate::engine::Detector;
use crate::report::{Finding, Severity};
use tree_sitter::Tree;

pub struct HardcodedKeysDetector;

impl Detector for HardcodedKeysDetector {
    fn analyze(
        &self,
        tree: &Tree,
        source: &str,
        functions: &[FnInfo],
        _fields: &[FieldInfo],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for func in functions {
            // Check runtime::put_key
            let hardcoded_lines =
                ast::find_string_literal_args_in_fn(tree, func, source, "runtime::put_key");
            for line in hardcoded_lines {
                findings.push(Finding {
                    id: format!("S402-HK-{:03}", findings.len() + 1),
                    severity: Severity::Low,
                    title: "Hardcoded storage key".to_string(),
                    description: "Hardcoded key names reduce upgradability. Consider using constants or configurable key names.".to_string(),
                    line,
                    pattern: "hardcoded_key".to_string(),
                    ai_explanation: None,
                });
            }

            // Check storage::new_uref with string args
            let uref_lines =
                ast::find_string_literal_args_in_fn(tree, func, source, "storage::new_uref");
            for line in uref_lines {
                findings.push(Finding {
                    id: format!("S402-HK-{:03}", findings.len() + 1),
                    severity: Severity::Low,
                    title: "Hardcoded storage key".to_string(),
                    description: "Hardcoded key names reduce upgradability. Consider using constants or configurable key names.".to_string(),
                    line,
                    pattern: "hardcoded_key".to_string(),
                    ai_explanation: None,
                });
            }
        }
        findings
    }
}
