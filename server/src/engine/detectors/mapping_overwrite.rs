use crate::ast::{self, FieldInfo, FnInfo};
use crate::engine::Detector;
use crate::report::{Finding, Severity};
use tree_sitter::Tree;

pub struct MappingOverwriteDetector;

impl Detector for MappingOverwriteDetector {
    fn analyze(
        &self,
        tree: &Tree,
        source: &str,
        functions: &[FnInfo],
        fields: &[FieldInfo],
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        let mapping_fields: Vec<&FieldInfo> = fields
            .iter()
            .filter(|f| f.type_name.contains("Mapping"))
            .collect();

        for func in functions {
            for mfield in &mapping_fields {
                let set_calls = ast::find_method_calls_in_fn(tree, func, source, "set");
                for call in &set_calls {
                    if call.receiver.contains(&mfield.name)
                        && !ast::body_contains_guard(tree, func, source)
                    {
                        findings.push(Finding {
                            id: format!("S402-MO-{:03}", findings.len() + 1),
                            severity: Severity::Critical,
                            title: format!("Unchecked Mapping overwrite on '{}'", mfield.name),
                            description: format!(
                                "Direct write to Mapping '{}' without authorization or guard check. Attackers can overwrite other users' data.",
                                mfield.name
                            ),
                            line: call.line,
                            pattern: "odra_mapping_overwrite".to_string(),
                            ai_explanation: None,
                        });
                        break; // one finding per mapping per function
                    }
                }
            }
        }
        findings
    }
}
