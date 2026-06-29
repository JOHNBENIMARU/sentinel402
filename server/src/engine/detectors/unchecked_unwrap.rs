use crate::ast::{self, FieldInfo, FnInfo};
use crate::engine::Detector;
use crate::report::{Finding, Severity};
use tree_sitter::Tree;

pub struct UncheckedUnwrapDetector;

impl Detector for UncheckedUnwrapDetector {
    fn analyze(
        &self,
        tree: &Tree,
        source: &str,
        functions: &[FnInfo],
        _fields: &[FieldInfo],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for func in functions {
            let unwrap_lines = ast::find_unwrap_calls_in_fn(tree, func, source);
            for line in unwrap_lines {
                findings.push(Finding {
                    id: format!("S402-UU-{:03}", findings.len() + 1),
                    severity: Severity::Medium,
                    title: "Unchecked unwrap() may panic".to_string(),
                    description: format!(
                        "Line {}: unwrap() will panic on None/Err. Use proper error handling in production contracts.",
                        line
                    ),
                    line,
                    pattern: "unchecked_unwrap".to_string(),
                    ai_explanation: None,
                });
            }
        }
        findings
    }
}
