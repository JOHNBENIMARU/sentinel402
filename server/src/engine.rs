use crate::report::Finding;

/// Vulnerability pattern detectors for Casper/Odra smart contracts
pub fn analyze(source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let lines: Vec<&str> = source.lines().collect();
    
    let mut has_transfer = false;
    let mut has_approve = false;

    // Pass 1: collect Mapping field names (e.g. "audits: Mapping<...>" → "audits")
    let mut mapping_fields: Vec<String> = Vec::new();
    for line in &lines {
        if line.contains("Mapping<") || line.contains("Mapping <") {
            // Extract field name: "    audits: Mapping<String, String>," → "audits"
            let trimmed = line.trim();
            if let Some(colon_pos) = trimmed.find(':') {
                let field = trimmed[..colon_pos].trim().to_string();
                // Strip visibility modifiers
                let field = field.replace("pub ", "").replace("pub(crate) ", "").trim().to_string();
                if !field.is_empty() && !field.contains(' ') {
                    mapping_fields.push(field);
                }
            }
        }
    }

    // Pass 2: detect vulnerabilities line by line
    for (i, line) in lines.iter().enumerate() {
        let line_num = i + 1;

        // Track CEP-18 features
        if line.contains("fn transfer(") { has_transfer = true; }
        if line.contains("fn approve(") { has_approve = true; }

        // Odra: Unprotected state mutation on privileged function (missing policy/logic guard)
        if line.contains("pub fn") && (line.contains("set_") || line.contains("update_") || line.contains("mint") || line.contains("record_") || line.contains("delete_") || line.contains("remove_")) {
            if !has_logic_guard_nearby(&lines, i) {
                findings.push(Finding {
                    id: format!("S402-{:03}", findings.len() + 1),
                    severity: "DISASTER".to_string(),
                    title: "Unprotected State Mutation".to_string(),
                    description: "Public function modifies state but lacks caller validation, role checks, or assertion guards. May allow unauthorized access.".to_string(),
                    line: line_num,
                    pattern: "odra_unprotected_mutation".to_string(),
                    ai_explanation: None,
                });
            }
        }

        // Odra: Mapping arbitrary overwrite — check if any known mapping field is .set() without auth/logic check
        for field in &mapping_fields {
            let set_pattern = format!("{}.set(", field);
            let self_set = format!("self.{}.set(", field);
            if (line.contains(&set_pattern) || line.contains(&self_set)) && !has_logic_guard_nearby(&lines, i) {
                findings.push(Finding {
                    id: format!("S402-{:03}", findings.len() + 1),
                    severity: "CATASTROPHE".to_string(),
                    title: format!("Unchecked Mapping overwrite on '{}'", field),
                    description: format!("Direct write to Mapping '{}' without authorization or guard check. Attackers can overwrite other users' data.", field),
                    line: line_num,
                    pattern: "odra_mapping_overwrite".to_string(),
                    ai_explanation: None,
                });
                break; // one finding per line
            }
        }

        // Casper: Unsafe transfer_from_purse_to_account
        if line.contains("transfer_from_purse_to_account") && !line.contains(".unwrap_or_revert") && !line.contains("match") {
            findings.push(Finding {
                id: format!("S402-{:03}", findings.len() + 1),
                severity: "DISASTER".to_string(),
                title: "Unsafe purse transfer".to_string(),
                description: "transfer_from_purse_to_account returns a TransferResult. Failing to handle it allows execution to continue after a failed transfer.".to_string(),
                line: line_num,
                pattern: "casper_unsafe_transfer".to_string(),
                ai_explanation: None,
            });
        }

        // Reentrancy: external call before state update
        if line.contains("runtime::call_contract") && !has_state_update_before(source, i) {
            findings.push(Finding {
                id: format!("S402-{:03}", findings.len() + 1),
                severity: "DISASTER".to_string(),
                title: "Potential reentrancy via runtime::call_contract".to_string(),
                description: "External contract call detected. Verify state is updated before this call (CEI pattern).".to_string(),
                line: line_num,
                pattern: "reentrancy".to_string(),
                ai_explanation: None,
            });
        }

        // Unchecked unwrap
        if line.contains(".unwrap()") && !line.trim_start().starts_with("//") {
            findings.push(Finding {
                id: format!("S402-{:03}", findings.len() + 1),
                severity: "CALAMITY".to_string(),
                title: "Unchecked unwrap() may panic".to_string(),
                description: format!("Line {}: unwrap() will panic on None/Err. Use proper error handling in production contracts.", line_num),
                line: line_num,
                pattern: "unchecked_unwrap".to_string(),
                ai_explanation: None,
            });
        }

        // Unsafe arithmetic (no overflow check)
        if (line.contains(" + ") || line.contains(" * ")) && line.contains("U256") {
            findings.push(Finding {
                id: format!("S402-{:03}", findings.len() + 1),
                severity: "CALAMITY".to_string(),
                title: "Potential arithmetic overflow on U256".to_string(),
                description: "U256 arithmetic without checked_add/checked_mul. May overflow silently.".to_string(),
                line: line_num,
                pattern: "overflow".to_string(),
                ai_explanation: None,
            });
        }

        // Casper: hardcoded key names (bad practice for upgradability)
        if (line.contains("runtime::put_key(\"") || line.contains("storage::new_uref(")) && !line.trim_start().starts_with("//") {
            findings.push(Finding {
                id: format!("S402-{:03}", findings.len() + 1),
                severity: "HAZARD".to_string(),
                title: "Hardcoded storage key".to_string(),
                description: "Hardcoded key names reduce upgradability. Consider using constants or configurable key names.".to_string(),
                line: line_num,
                pattern: "hardcoded_key".to_string(),
                ai_explanation: None,
            });
        }
    }

    // CEP-18 Non-compliance
    if has_transfer && !has_approve {
        findings.push(Finding {
            id: format!("S402-{:03}", findings.len() + 1),
            severity: "HAZARD".to_string(),
            title: "CEP-18 Non-compliance: Missing approve".to_string(),
            description: "Contract implements transfer() but is missing approve(). Fails CEP-18 standard compliance.".to_string(),
            line: 0,
            pattern: "cep18_compliance".to_string(),
            ai_explanation: None,
        });
    }

    findings
}

fn has_state_update_before(source: &str, call_line: usize) -> bool {
    let lines: Vec<&str> = source.lines().collect();
    let start = if call_line > 5 { call_line - 5 } else { 0 };
    for i in start..call_line {
        if lines[i].contains("storage::write") || lines[i].contains(".set(") {
            return true;
        }
    }
    false
}

fn has_logic_guard_nearby(lines: &[&str], entry_line: usize) -> bool {
    let start = if entry_line > 5 { entry_line - 5 } else { 0 };
    let end = (entry_line + 20).min(lines.len());
    for i in start..end {
        let l = lines[i];
        if l.contains("env::caller()") 
            || l.contains("self.env().caller()") 
            || l.contains("get_caller") 
            || l.contains("assert!")
            || l.contains("assert_eq!")
            || l.contains("revert(")
            || l.contains("unwrap_or_revert")
            || l.contains("access_control")
            || l.contains("assert_role")
            || l.contains("is_admin") 
            || l.contains("only_owner")
        {
            return true;
        }
    }
    false
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
        let found = findings.iter().any(|f| f.pattern == "odra_unprotected_mutation");
        assert!(found, "Should detect unprotected state mutation on set_ fn without guards");
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
        let found = findings.iter().any(|f| f.pattern == "odra_unprotected_mutation");
        assert!(!found, "Should NOT detect unprotected state mutation when logic guard is present");
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
        let unprotected = findings.iter().any(|f| f.pattern == "odra_unprotected_mutation");
        assert!(!unprotected, "AccessControl assert_role should be recognized as a valid logic guard");
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
        let found = findings.iter().any(|f| f.pattern == "odra_mapping_overwrite");
        assert!(found, "Should flag arbitrary Mapping overwrite if no auth guard is present");
    }

    #[test]
    fn test_unsafe_purse_transfer() {
        let code = r#"
            let result = transfer_from_purse_to_account(src, dst, amount);
            // execution continues without checking result
        "#;
        let findings = analyze(code);
        let found = findings.iter().any(|f| f.pattern == "casper_unsafe_transfer");
        assert!(found, "Should catch unsafe purse transfer lacking unwrap_or_revert / match");
    }

    #[test]
    fn test_reentrancy_detection() {
        let code = r#"
            runtime::call_contract(target, "receive", args);
            self.state.set(updated);
        "#;
        let findings = analyze(code);
        let found = findings.iter().any(|f| f.pattern == "reentrancy");
        assert!(found, "Should flag potential reentrancy if state update is after call_contract");
    }

    #[test]
    fn test_no_reentrancy_with_cei() {
        let code = r#"
            self.state.set(updated);
            runtime::call_contract(target, "receive", args);
        "#;
        let findings = analyze(code);
        let found = findings.iter().any(|f| f.pattern == "reentrancy");
        assert!(!found, "Should not flag reentrancy when state update occurs before call_contract");
    }

    #[test]
    fn test_arithmetic_overflow_detection() {
        let code = r#"
            let result: U256 = val1 + val2;
        "#;
        let findings = analyze(code);
        let found = findings.iter().any(|f| f.pattern == "overflow");
        assert!(found, "Should catch potential arithmetic overflow on standard + operator with U256");
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
        assert!(found, "Should catch CEP-18 non-compliance (transfer without approve)");
    }

    #[test]
    fn test_cep18_compliance() {
        let code = r#"
            pub fn transfer(&mut self, recipient: Address, amount: U256) {}
            pub fn approve(&mut self, spender: Address, amount: U256) {}
        "#;
        let findings = analyze(code);
        let found = findings.iter().any(|f| f.pattern == "cep18_compliance");
        assert!(!found, "Should NOT flag CEP-18 non-compliance when both transfer and approve are present");
    }

    #[test]
    fn test_commented_code_ignored() {
        let code = r#"
            // let x = y.unwrap();
            // runtime::put_key("hardcoded");
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
            runtime::put_key("my_awesome_key", key);
        "#;
        let findings = analyze(code);
        let found = findings.iter().any(|f| f.pattern == "hardcoded_key");
        assert!(found, "Should detect hardcoded storage keys");
    }

    #[test]
    fn test_mapping_visibilities() {
        let code = r#"
            pub(crate) users: Mapping<Address, String>,
            impl Contract {
                pub fn update_user(&mut self, user: Address, info: String) {
                    self.users.set(&user, info);
                }
            }
        "#;
        let findings = analyze(code);
        let found = findings.iter().any(|f| f.pattern == "odra_mapping_overwrite");
        assert!(found, "Should detect mapping overwrite even with pub(crate) visibility modifiers");
    }

    #[test]
    fn test_arithmetic_multiplication_overflow() {
        let code = r#"
            let price: U256 = quantity * price_per_unit;
        "#;
        let findings = analyze(code);
        let found = findings.iter().any(|f| f.pattern == "overflow");
        assert!(found, "Should detect multiplication overflow on U256");
    }

    #[test]
    fn test_edge_case_near_file_bounds() {
        let code = "self.balances.set(&user, val);";
        let findings = analyze(code);
        assert_eq!(findings.len(), 0, "Should analyze small strings without out-of-bounds panic");
    }
}


