use crate::ast::{self, FieldInfo, FnInfo};
use crate::engine::Detector;
use crate::report::{Finding, Severity};
use tree_sitter::Tree;

pub struct ReentrancyDetector;

impl Detector for ReentrancyDetector {
    fn analyze(
        &self,
        tree: &Tree,
        source: &str,
        functions: &[FnInfo],
        _fields: &[FieldInfo],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for func in functions {
            let ext_calls =
                ast::find_function_calls_in_fn(tree, func, source, "runtime::call_contract");
            for call in &ext_calls {
                if !ast::has_state_update_before_line(tree, func, source, call.line) {
                    findings.push(Finding {
                        id: format!("S402-RE-{:03}", findings.len() + 1),
                        severity: Severity::High,
                        title: "Potential reentrancy via runtime::call_contract".to_string(),
                        description: "External contract call detected. Verify state is updated before this call (CEI pattern).".to_string(),
                        line: call.line,
                        pattern: "reentrancy".to_string(),
                        ai_explanation: None,
                    });
                }
            }
        }
        findings
    }
}
