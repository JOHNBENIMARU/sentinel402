use crate::ast::{self, FieldInfo, FnInfo};
use crate::engine::Detector;
use crate::report::{Finding, Severity};
use tree_sitter::Tree;

pub struct UnsafeTransferDetector;

impl Detector for UnsafeTransferDetector {
    fn analyze(
        &self,
        tree: &Tree,
        source: &str,
        functions: &[FnInfo],
        _fields: &[FieldInfo],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for func in functions {
            let transfer_calls =
                ast::find_function_calls_in_fn(tree, func, source, "transfer_from_purse_to_account");
            for call in &transfer_calls {
                if !ast::is_call_result_handled(tree, func, source, call.line) {
                    findings.push(Finding {
                        id: format!("S402-UT-{:03}", findings.len() + 1),
                        severity: Severity::High,
                        title: "Unsafe purse transfer".to_string(),
                        description: "transfer_from_purse_to_account returns a TransferResult. Failing to handle it allows execution to continue after a failed transfer.".to_string(),
                        line: call.line,
                        pattern: "casper_unsafe_transfer".to_string(),
                        ai_explanation: None,
                    });
                }
            }
        }
        findings
    }
}
