use crate::ast::{self, FieldInfo, FnInfo};
use crate::engine::Detector;
use crate::report::{Finding, Severity};
use tree_sitter::Tree;

pub struct DivideByZeroDetector;

impl Detector for DivideByZeroDetector {
    fn analyze(
        &self,
        tree: &Tree,
        source: &str,
        functions: &[FnInfo],
        _fields: &[FieldInfo],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for func in functions {
            let div_lines = ast::find_division_in_fn(tree, func, source);
            for line in div_lines {
                findings.push(Finding {
                    id: format!("S402-DZ-{:03}", findings.len() + 1),
                    severity: Severity::Medium,
                    title: "Potential divide by zero".to_string(),
                    description:
                        "Unchecked division (/) or modulo (%) can panic if the denominator is 0. Verify the denominator or use checked_div()."
                            .to_string(),
                    line,
                    pattern: "divide_by_zero".to_string(),
                    ai_explanation: None,
                });
            }
        }
        
        findings
    }
}
