use crate::ast::{self, FieldInfo, FnInfo};
use crate::engine::{is_privileged_fn_name, Detector};
use crate::report::{Finding, Severity};
use tree_sitter::Tree;

pub struct UnprotectedMutationDetector;

impl Detector for UnprotectedMutationDetector {
    fn analyze(
        &self,
        tree: &Tree,
        source: &str,
        functions: &[FnInfo],
        _fields: &[FieldInfo],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        for func in functions {
            if func.is_public
                && is_privileged_fn_name(&func.name)
                && !ast::body_contains_guard(tree, func, source)
            {
                findings.push(Finding {
                    id: format!("S402-UM-{:03}", findings.len() + 1), // Using a prefix + length is fine, will be hashed later
                    severity: Severity::High,
                    title: "Unprotected State Mutation".to_string(),
                    description: "Public function modifies state but lacks caller validation, role checks, or assertion guards. May allow unauthorized access.".to_string(),
                    line: func.start_line,
                    pattern: "odra_unprotected_mutation".to_string(),
                    ai_explanation: None,
                });
            }
        }
        findings
    }
}
