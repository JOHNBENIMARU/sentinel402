use crate::ast::{FieldInfo, FnInfo};
use crate::engine::Detector;
use crate::report::{Finding, Severity};
use crate::taint;
use tree_sitter::Tree;

pub struct TaintedInputDetector;

impl Detector for TaintedInputDetector {
    fn analyze(
        &self,
        tree: &Tree,
        source: &str,
        functions: &[FnInfo],
        _fields: &[FieldInfo],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // These are critical sinks where tainted inputs shouldn't end up unvalidated
        let sinks = vec![
            "call_contract",
            "transfer_from_purse_to_account",
            "transfer_from_purse_to_purse",
            ".set(",
        ];

        for func in functions {
            // Check only public functions
            if !func.is_public {
                continue;
            }

            let tainted_usages = taint::find_tainted_usages(tree, func, source, &sinks);

            for (arg_name, line) in tainted_usages {
                findings.push(Finding {
                    id: format!("S402-TI-{:03}", findings.len() + 1),
                    severity: Severity::High,
                    title: "Tainted Input used in Critical Sink".to_string(),
                    description: format!(
                        "Argument '{}' is passed directly into a critical operation (e.g. transfer or call) without prior sanitization/validation.",
                        arg_name
                    ),
                    line,
                    pattern: "tainted_input_unvalidated".to_string(),
                    ai_explanation: None,
                });
            }
        }

        findings
    }
}
