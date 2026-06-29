use crate::ast::{self, FieldInfo, FnInfo};
use crate::engine::Detector;
use crate::report::{Finding, Severity};
use tree_sitter::Tree;

pub struct ArithmeticOverflowDetector;

impl Detector for ArithmeticOverflowDetector {
    fn analyze(
        &self,
        tree: &Tree,
        source: &str,
        functions: &[FnInfo],
        _fields: &[FieldInfo],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for func in functions {
            let overflow_lines = ast::find_unsafe_arithmetic_in_fn(tree, func, source);
            for line in overflow_lines {
                findings.push(Finding {
                    id: format!("S402-AO-{:03}", findings.len() + 1),
                    severity: Severity::Medium,
                    title: "Potential arithmetic overflow on U256".to_string(),
                    description:
                        "U256 arithmetic without checked_add/checked_mul. May overflow silently."
                            .to_string(),
                    line,
                    pattern: "overflow".to_string(),
                    ai_explanation: None,
                });
            }
        }
        findings
    }
}
