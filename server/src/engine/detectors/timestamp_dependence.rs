use crate::ast::{self, FieldInfo, FnInfo};
use crate::engine::Detector;
use crate::report::{Finding, Severity};
use tree_sitter::Tree;

pub struct TimestampDependenceDetector;

impl Detector for TimestampDependenceDetector {
    fn analyze(
        &self,
        tree: &Tree,
        source: &str,
        functions: &[FnInfo],
        _fields: &[FieldInfo],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for func in functions {
            // Check for Odra's self.env().get_block_time()
            let block_time_calls =
                ast::find_method_calls_in_fn(tree, func, source, "get_block_time");
            for call in &block_time_calls {
                findings.push(Finding {
                    id: format!("S402-TD-{:03}", findings.len() + 1),
                    severity: Severity::Low,
                    title: "Timestamp Dependence".to_string(),
                    description: "Using block time for logic or randomness is unsafe, as validators can manipulate it.".to_string(),
                    line: call.line,
                    pattern: "timestamp_dependence".to_string(),
                    ai_explanation: None,
                });
            }

            // Check for Casper's runtime::get_blocktime()
            let blocktime_calls =
                ast::find_function_calls_in_fn(tree, func, source, "get_blocktime");
            for call in &blocktime_calls {
                findings.push(Finding {
                    id: format!("S402-TD-{:03}", findings.len() + 1),
                    severity: Severity::Low,
                    title: "Timestamp Dependence".to_string(),
                    description: "Using block time for logic or randomness is unsafe, as validators can manipulate it.".to_string(),
                    line: call.line,
                    pattern: "timestamp_dependence".to_string(),
                    ai_explanation: None,
                });
            }
        }
        
        findings
    }
}
