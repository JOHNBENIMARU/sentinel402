pub mod detectors;

use crate::ast;
use crate::report::Finding;
use tree_sitter::Tree;

pub trait Detector {
    fn analyze(
        &self,
        tree: &Tree,
        source: &str,
        functions: &[ast::FnInfo],
        fields: &[ast::FieldInfo],
    ) -> Vec<Finding>;
}

/// Privileged function name prefixes that should be guarded.
pub const PRIVILEGED_PREFIXES: &[&str] = &[
    "set_", "update_", "mint", "record_", "delete_", "remove_",
];

pub fn is_privileged_fn_name(name: &str) -> bool {
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

    let detectors = detectors::get_all_detectors();

    for detector in detectors {
        let mut f = detector.analyze(&tree, source, &functions, &fields);
        findings.append(&mut f);
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
        assert!(
            findings.is_empty() || findings.len() > 0,
            "Should analyze small strings without out-of-bounds panic"
        );
    }

    #[test]
    fn test_tainted_input_unvalidated() {
        let code = r#"
            pub fn transfer_to_user(&mut self, target_address: Address) {
                runtime::call_contract(target_address, "transfer", args);
            }
        "#;
        let findings = analyze(code);
        let found = findings.iter().any(|f| f.pattern == "tainted_input_unvalidated");
        assert!(found, "Should catch unvalidated tainted input into a sink");
    }

    #[test]
    fn test_tainted_input_sanitized() {
        let code = r#"
            pub fn transfer_to_user(&mut self, target_address: Address) {
                assert!(target_address == self.env().caller());
                runtime::call_contract(target_address, "transfer", args);
            }
        "#;
        let findings = analyze(code);
        let found = findings.iter().any(|f| f.pattern == "tainted_input_unvalidated");
        assert!(!found, "Should NOT flag tainted input if it has been sanitized with assert");
    }

    #[test]
    fn test_multi_vector_god_class() {
        // A single contract function that contains multiple severe vulnerabilities.
        // It must NOT choke the analyzer, and it MUST return all distinct findings.
        let code = r#"
            pub fn set_hack_me_god_class(&mut self, user: Address, amount: U256) {
                // 4. Reentrancy (call before any state update)
                let ext_call = runtime::call_contract(user, "receive", args);

                // 1. Unprotected state mutation
                self.admin.set(user);

                // 2. Division by zero
                let reward = amount / 0;

                // 3. Tainted input into critical sink
                runtime::call_contract(user, "send_funds", args);

                // 5. Hardcoded key
                runtime::put_key("secret_admin_key", key);
            }
        "#;
        let findings = analyze(code);
        
        let has_unprotected = findings.iter().any(|f| f.pattern == "odra_unprotected_mutation");
        let has_div_zero = findings.iter().any(|f| f.pattern == "divide_by_zero");
        let has_tainted = findings.iter().any(|f| f.pattern == "tainted_input_unvalidated");
        let has_reentrancy = findings.iter().any(|f| f.pattern == "reentrancy");
        let has_hardcoded = findings.iter().any(|f| f.pattern == "hardcoded_key");

        assert!(has_unprotected, "Missing Unprotected Mutation");
        assert!(has_div_zero, "Missing Division by Zero");
        assert!(has_tainted, "Missing Tainted Input");
        assert!(has_reentrancy, "Missing Reentrancy");
        assert!(has_hardcoded, "Missing Hardcoded Key");
    }

    #[test]
    fn test_ast_dos_resilience() {
        // Generate an extremely deep nested AST to trigger Stack Overflow
        // if the tree-sitter parsing or AST walking is done with naive recursion.
        let depth = 200;
        let mut code = String::from("pub fn dos_test() {\n");
        for _ in 0..depth {
            code.push_str("if true {\n");
        }
        code.push_str("let a = 1;\n");
        for _ in 0..depth {
            code.push_str("}\n");
        }
        code.push_str("}\n");

        // If this crashes with a stack overflow, we fail the test.
        // Otherwise, it should just return 0 findings gracefully.
        let findings = analyze(&code);
        assert!(findings.is_empty(), "Deeply nested code should parse without findings and not crash.");
    }
}
