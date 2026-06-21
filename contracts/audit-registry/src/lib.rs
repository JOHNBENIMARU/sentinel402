#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
extern crate alloc;

use odra::prelude::*;

/// On-chain audit record stored in Casper via Odra
#[odra::module]
pub struct AuditRegistry {
    /// Mapping: audit_id (String) -> JSON audit record
    audits: Mapping<String, String>,
    /// Contract owner for authorization
    owner: Var<Address>,
}

#[odra::module]
impl AuditRegistry {
    /// Initialize with deployer as owner
    pub fn init(&mut self) {
        let caller = self.env().caller();
        self.owner.set(caller);
    }

    /// Record an audit result on-chain. Only callable by owner.
    pub fn record_audit(
        &mut self,
        audit_id: String,
        contract_hash: String,
        risk_score: String,
        total_findings: u32,
        timestamp: u64,
    ) {
        let caller = self.env().caller();
        let owner = self.owner.get_or_revert_with(OdraError::user(1));
        if caller != owner {
            self.env().revert(OdraError::user(2));
        }

        let record = format!(
            "{{\"contract_hash\":\"{}\",\"risk_score\":\"{}\",\"total_findings\":{},\"timestamp\":{}}}",
            contract_hash, risk_score, total_findings, timestamp
        );
        self.audits.set(&audit_id, record);
    }

    /// Get audit record by ID
    pub fn get_audit(&self, audit_id: String) -> Option<String> {
        self.audits.get(&audit_id)
    }

    /// Get contract owner
    pub fn get_owner(&self) -> Address {
        self.owner.get_or_revert_with(OdraError::user(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use odra::host::{Deployer, NoArgs};

    #[test]
    fn test_owner_is_set_on_init() {
        let env = odra_test::env();
        let registry = AuditRegistry::deploy(&env, NoArgs);
        let owner = registry.get_owner();
        assert_eq!(owner, env.get_account(0));
    }

    #[test]
    fn test_record_and_get_audit() {
        let env = odra_test::env();
        let mut registry = AuditRegistry::deploy(&env, NoArgs);

        registry.record_audit(
            "audit-abc123".to_string(),
            "hash-contract-456".to_string(),
            "DISASTER".to_string(),
            3,
            1719000000,
        );

        let result = registry.get_audit("audit-abc123".to_string());
        assert!(result.is_some());
        let record = result.unwrap();
        assert!(record.contains("DISASTER"));
        assert!(record.contains("hash-contract-456"));
        assert!(record.contains("1719000000"));
    }

    #[test]
    fn test_get_nonexistent_audit() {
        let env = odra_test::env();
        let registry = AuditRegistry::deploy(&env, NoArgs);
        let result = registry.get_audit("does-not-exist".to_string());
        assert!(result.is_none());
    }

    #[test]
    #[should_panic]
    fn test_unauthorized_record_fails() {
        let env = odra_test::env();
        let mut registry = AuditRegistry::deploy(&env, NoArgs);

        // Switch to a different account
        env.set_caller(env.get_account(1));

        registry.record_audit(
            "audit-evil".to_string(),
            "hash-evil".to_string(),
            "HAZARD".to_string(),
            0,
            0,
        );
    }
}
