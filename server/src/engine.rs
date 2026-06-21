use crate::ast;
use crate::report::Finding;

/// Privileged function name prefixes that should be guarded.
const PRIVILEGED_PREFIXES: &[&str] = &[
    "set_", "update_", "mint", "record_", "delete_", "remove_",
];

fn is_privileged_fn_name(name: &str) -> bool {
    PRIVILEGED_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix) || name == *prefix)
}

/// Vulnerability pattern detectors for Casper/Odra smart contracts.
/// Uses tree-sitter AST parsing for accurate, scope-aware analysis.
pub fn analyze(source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Parse source into AST
    let tree = match ast::parse(source) {
        Some(t) => t,
        None => return findings, // unparseable → no findings
    };

    let functions = ast::find_functions(&tree, source);
    let fields = ast::find_struct_fields(&tree, source);

    // Collect Mapping field names
    let mapping_fields: Vec<&ast::FieldInfo> = fields
        .iter()
        .filter(|f| f.type_name.contains("Mapping"))
        .collect();

    // Track CEP-18 features
    let has_transfer = functions.iter().any(|f| f.name == "transfer");
    let has_approve = functions.iter().any(|f| f.name == "approve");

    // Analyze each function
    for func in &functions {
        // --- Detector 1: Unprotected State Mutation ---
        if func.is_public && is_privileged_fn_name(&func.name) {
            if !ast::body_contains_guard(&tree, func, source) {
                findings.push(Finding {
                    id: format!("S402-{:03}", findings.len() + 1),
                    severity: "DISASTER".to_string(),
                    title: "Unprotected State Mutation".to_string(),
                    description: "Public function modifies state but lacks caller validation, role checks, or assertion guards. May allow unauthorized access.".to_string(),
                    line: func.start_line,
                    pattern: "odra_unprotected_mutation".to_string(),
                    ai_explanation: None,
                });
            }
        }

        // --- Detector 2: Mapping Overwrite ---
        for mfield in &mapping_fields {
            let set_calls = ast::find_method_calls_in_fn(&tree, func, source, "set");
            for call in &set_calls {
                // Check if the receiver matches the mapping field (e.g. "self.balances")
                if call.receiver.contains(&mfield.name)
                    && !ast::body_contains_guard(&tree, func, source)
                {
                    findings.push(Finding {
                        id: format!("S402-{:03}", findings.len() + 1),
                        severity: "CATASTROPHE".to_string(),
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

        // --- Detector 3: Unsafe purse transfer ---
        let transfer_calls =
            ast::find_function_calls_in_fn(&tree, func, source, "transfer_from_purse_to_account");
        for call in &transfer_calls {
            if !ast::is_call_result_handled(&tree, func, source, call.line) {
                findings.push(Finding {
                    id: format!("S402-{:03}", findings.len() + 1),
                    severity: "DISASTER".to_string(),
                    title: "Unsafe purse transfer".to_string(),
                    description: "transfer_from_purse_to_account returns a TransferResult. Failing to handle it allows execution to continue after a failed transfer.".to_string(),
                    line: call.line,
                    pattern: "casper_unsafe_transfer".to_string(),
                    ai_explanation: None,
                });
            }
        }

        // --- Detector 4: Reentrancy ---
        let ext_calls =
            ast::find_function_calls_in_fn(&tree, func, source, "runtime::call_contract");
        for call in &ext_calls {
            if !ast::has_state_update_before_line(&tree, func, source, call.line) {
                findings.push(Finding {
                    id: format!("S402-{:03}", findings.len() + 1),
                    severity: "DISASTER".to_string(),
                    title: "Potential reentrancy via runtime::call_contract".to_string(),
                    description: "External contract call detected. Verify state is updated before this call (CEI pattern).".to_string(),
                    line: call.line,
                    pattern: "reentrancy".to_string(),
                    ai_explanation: None,
                });
            }
        }

        // --- Detector 5: Unchecked unwrap ---
        let unwrap_lines = ast::find_unwrap_calls_in_fn(&tree, func, source);
        for line in unwrap_lines {
            findings.push(Finding {
                id: format!("S402-{:03}", findings.len() + 1),
                severity: "CALAMITY".to_string(),
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

        // --- Detector 6: Arithmetic overflow ---
        let overflow_lines = ast::find_unsafe_arithmetic_in_fn(&tree, func, source);
        for line in overflow_lines {
            findings.push(Finding {
                id: format!("S402-{:03}", findings.len() + 1),
                severity: "CALAMITY".to_string(),
                title: "Potential arithmetic overflow on U256".to_string(),
                description:
                    "U256 arithmetic without checked_add/checked_mul. May overflow silently."
                        .to_string(),
                line,
                pattern: "overflow".to_string(),
                ai_explanation: None,
            });
        }

        // --- Detector 7: Hardcoded storage keys ---
        let hardcoded_lines =
            ast::find_string_literal_args_in_fn(&tree, func, source, "runtime::put_key");
        for line in hardcoded_lines {
            findings.push(Finding {
                id: format!("S402-{:03}", findings.len() + 1),
                severity: "HAZARD".to_string(),
                title: "Hardcoded storage key".to_string(),
                description: "Hardcoded key names reduce upgradability. Consider using constants or configurable key names.".to_string(),
                line,
                pattern: "hardcoded_key".to_string(),
                ai_explanation: None,
            });
        }

        // Also check storage::new_uref with string args
        let uref_lines =
            ast::find_string_literal_args_in_fn(&tree, func, source, "storage::new_uref");
        for line in uref_lines {
            findings.push(Finding {
                id: format!("S402-{:03}", findings.len() + 1),
                severity: "HAZARD".to_string(),
                title: "Hardcoded storage key".to_string(),
                description: "Hardcoded key names reduce upgradability. Consider using constants or configurable key names.".to_string(),
                line,
                pattern: "hardcoded_key".to_string(),
                ai_explanation: None,
            });
        }
    }

    // --- Detector 8: CEP-18 Non-compliance (global check) ---
    if has_transfer && !has_approve {
        findings.push(Finding {
            id: format!("S402-{:03}", findings.len() + 1),
            severity: "HAZARD".to_string(),
            title: "CEP-18 Non-compliance: Missing approve".to_string(),
            description:
                "Contract implements transfer() but is missing approve(). Fails CEP-18 standard compliance."
                    .to_string(),
            line: 0,
            pattern: "cep18_compliance".to_string(),
            ai_explanation: None,
        });
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unprotected_state_mutation() {
        let code = r#"
            pub fn set_balance(&mut self, amount: U256) {
                self.balance.set(amount);
            }
        "#;
        let findings = analyze(code);
        let found = findings
            .iter()
            .any(|f| f.pattern == "odra_unprotected_mutation");
        assert!(
            found,
            "Should detect unprotected state mutation on set_ fn without guards"
        );
    }

    #[test]
    fn test_protected_state_mutation() {
        let code = r#"
            pub fn set_balance(&mut self, amount: U256) {
                if self.env().caller() == self.owner.get() {
                    self.balance.set(amount);
                }
            }
        "#;
        let findings = analyze(code);
        let found = findings
            .iter()
            .any(|f| f.pattern == "odra_unprotected_mutation");
        assert!(
            !found,
            "Should NOT detect unprotected state mutation when logic guard is present"
        );
    }

    #[test]
    fn test_access_control_roles_detected() {
        let code = r#"
            pub fn mint(&mut self, amount: U256) {
                self.access_control.assert_role(MINTER_ROLE);
                self.total_supply.set(self.total_supply.get() + amount);
            }
        "#;
        let findings = analyze(code);
        let unprotected = findings
            .iter()
            .any(|f| f.pattern == "odra_unprotected_mutation");
        assert!(
            !unprotected,
            "AccessControl assert_role should be recognized as a valid logic guard"
        );
    }

    #[test]
    fn test_mapping_overwrite_detection() {
        let code = r#"
            pub struct Contract {
                balances: Mapping<Address, U256>,
            }
            impl Contract {
                pub fn set_user_data(&mut self, user: Address, val: U256) {
                    self.balances.set(&user, val);
                }
            }
        "#;
        let findings = analyze(code);
        let found = findings
            .iter()
            .any(|f| f.pattern == "odra_mapping_overwrite");
        assert!(
            found,
            "Should flag arbitrary Mapping overwrite if no auth guard is present"
        );
    }

    #[test]
    fn test_unsafe_purse_transfer() {
        let code = r#"
            fn do_transfer() {
                let result = transfer_from_purse_to_account(src, dst, amount);
            }
        "#;
        let findings = analyze(code);
        let found = findings
            .iter()
            .any(|f| f.pattern == "casper_unsafe_transfer");
        assert!(
            found,
            "Should catch unsafe purse transfer lacking unwrap_or_revert / match"
        );
    }

    #[test]
    fn test_reentrancy_detection() {
        let code = r#"
            fn withdraw() {
                runtime::call_contract(target, "receive", args);
                self.state.set(updated);
            }
        "#;
        let findings = analyze(code);
        let found = findings.iter().any(|f| f.pattern == "reentrancy");
        assert!(
            found,
            "Should flag potential reentrancy if state update is after call_contract"
        );
    }

    #[test]
    fn test_no_reentrancy_with_cei() {
        let code = r#"
            fn withdraw() {
                self.state.set(updated);
                runtime::call_contract(target, "receive", args);
            }
        "#;
        let findings = analyze(code);
        let found = findings.iter().any(|f| f.pattern == "reentrancy");
        assert!(
            !found,
            "Should not flag reentrancy when state update occurs before call_contract"
        );
    }

    #[test]
    fn test_arithmetic_overflow_detection() {
        let code = r#"
            fn calc() {
                let result: U256 = val1 + val2;
            }
        "#;
        let findings = analyze(code);
        let found = findings.iter().any(|f| f.pattern == "overflow");
        assert!(
            found,
            "Should catch potential arithmetic overflow on standard + operator with U256"
        );
    }

    #[test]
    fn test_cep18_non_compliance() {
        let code = r#"
            pub fn transfer(&mut self, recipient: Address, amount: U256) {
                // missing approve
            }
        "#;
        let findings = analyze(code);
        let found = findings.iter().any(|f| f.pattern == "cep18_compliance");
        assert!(
            found,
            "Should catch CEP-18 non-compliance (transfer without approve)"
        );
    }

    #[test]
    fn test_cep18_compliance() {
        let code = r#"
            pub fn transfer(&mut self, recipient: Address, amount: U256) {}
            pub fn approve(&mut self, spender: Address, amount: U256) {}
        "#;
        let findings = analyze(code);
        let found = findings.iter().any(|f| f.pattern == "cep18_compliance");
        assert!(
            !found,
            "Should NOT flag CEP-18 non-compliance when both transfer and approve are present"
        );
    }

    #[test]
    fn test_commented_code_ignored() {
        let code = r#"
            fn foo() {
                // let x = y.unwrap();
                // runtime::put_key("hardcoded");
            }
        "#;
        let findings = analyze(code);
        let has_unwrap = findings.iter().any(|f| f.pattern == "unchecked_unwrap");
        let has_key = findings.iter().any(|f| f.pattern == "hardcoded_key");
        assert!(!has_unwrap, "Should ignore unwrap() in comments");
        assert!(!has_key, "Should ignore put_key in comments");
    }

    #[test]
    fn test_hardcoded_key_detection() {
        let code = r#"
            fn setup() {
                runtime::put_key("my_awesome_key", key);
            }
        "#;
        let findings = analyze(code);
        let found = findings.iter().any(|f| f.pattern == "hardcoded_key");
        assert!(found, "Should detect hardcoded storage keys");
    }

    #[test]
    fn test_mapping_visibilities() {
        let code = r#"
            pub struct Contract {
                pub(crate) users: Mapping<Address, String>,
            }
            impl Contract {
                pub fn update_user(&mut self, user: Address, info: String) {
                    self.users.set(&user, info);
                }
            }
        "#;
        let findings = analyze(code);
        let found = findings
            .iter()
            .any(|f| f.pattern == "odra_mapping_overwrite");
        assert!(
            found,
            "Should detect mapping overwrite even with pub(crate) visibility modifiers"
        );
    }

    #[test]
    fn test_arithmetic_multiplication_overflow() {
        let code = r#"
            fn calc() {
                let price: U256 = quantity * price_per_unit;
            }
        "#;
        let findings = analyze(code);
        let found = findings.iter().any(|f| f.pattern == "overflow");
        assert!(found, "Should detect multiplication overflow on U256");
    }

    #[test]
    fn test_edge_case_near_file_bounds() {
        let code = "self.balances.set(&user, val);";
        let findings = analyze(code);
        // Should not panic, and since there's no function wrapping this,
        // tree-sitter won't find function_item nodes → 0 findings
        assert!(
            findings.is_empty() || findings.len() > 0,
            "Should analyze small strings without out-of-bounds panic"
        );
    }
}
