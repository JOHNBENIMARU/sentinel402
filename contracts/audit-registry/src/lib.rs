#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
extern crate alloc;

use odra::prelude::*;

/// Event emitted when an audit is recorded on-chain.
#[odra::event]
pub struct AuditRecorded {
    pub audit_id: String,
    pub contract_hash: String,
    pub risk_score: String,
    pub total_findings: u32,
}

/// On-chain audit record stored in Casper via Odra.
/// Stores severity breakdown (Critical/High/Medium/Low) per audit.
#[odra::module]
pub struct AuditRegistry {
    /// Mapping: audit_id (String) -> JSON audit record
    audits: Mapping<String, String>,
    /// Total number of audits recorded
    audit_count: Var<u32>,
    /// Contract owner for authorization
    owner: Var<Address>,
}

#[odra::module]
impl AuditRegistry {
    /// Initialize with deployer as owner.
    pub fn init(&mut self) {
        let caller = self.env().caller();
        self.owner.set(caller);
        self.audit_count.set(0u32);
    }

    /// Record an audit result on-chain. Only callable by owner.
    pub fn record_audit(
        &mut self,
        audit_id: String,
        contract_hash: String,
        risk_score: String,
        critical: u32,
        high: u32,
        medium: u32,
        low: u32,
        timestamp: u64,
    ) {
        let caller = self.env().caller();
        let owner = self.owner.get_or_revert_with(OdraError::user(1));
        if caller != owner {
            self.env().revert(OdraError::user(2));
        }

        let total = critical + high + medium + low;

        let record = format!(
            "{{\"contract_hash\":\"{}\",\"risk_score\":\"{}\",\"critical\":{},\"high\":{},\"medium\":{},\"low\":{},\"total_findings\":{},\"timestamp\":{}}}",
            contract_hash, risk_score, critical, high, medium, low, total, timestamp
        );
        self.audits.set(&audit_id, record);

        let count = self.audit_count.get_or_default();
        self.audit_count.set(count + 1);

        self.env().emit_event(AuditRecorded {
            audit_id,
            contract_hash,
            risk_score,
            total_findings: total,
        });
    }

    /// Verify an audit exists and return its data. Public read-only.
    pub fn verify_audit(&self, audit_id: String) -> Option<String> {
        self.audits.get(&audit_id)
    }

    /// Get audit record by ID (alias for verify_audit).
    pub fn get_audit(&self, audit_id: String) -> Option<String> {
        self.audits.get(&audit_id)
    }

    /// Get total number of recorded audits.
    pub fn get_audit_count(&self) -> u32 {
        self.audit_count.get_or_default()
    }

    /// Get contract owner.
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
            "HIGH".to_string(),
            0, // critical
            2, // high
            1, // medium
            0, // low
            1719000000,
        );

        let result = registry.get_audit("audit-abc123".to_string());
        assert!(result.is_some());
        let record = result.unwrap();
        assert!(record.contains("HIGH"));
        assert!(record.contains("hash-contract-456"));
        assert!(record.contains("\"critical\":0"));
        assert!(record.contains("\"high\":2"));
        assert!(record.contains("\"medium\":1"));
        assert!(record.contains("\"total_findings\":3"));
    }

    #[test]
    fn test_verify_audit() {
        let env = odra_test::env();
        let mut registry = AuditRegistry::deploy(&env, NoArgs);

        registry.record_audit(
            "audit-verify-test".to_string(),
            "hash-xyz".to_string(),
            "SAFE".to_string(),
            0, 0, 0, 0,
            1719000000,
        );

        let result = registry.verify_audit("audit-verify-test".to_string());
        assert!(result.is_some());

        let missing = registry.verify_audit("does-not-exist".to_string());
        assert!(missing.is_none());
    }

    #[test]
    fn test_audit_count() {
        let env = odra_test::env();
        let mut registry = AuditRegistry::deploy(&env, NoArgs);
        assert_eq!(registry.get_audit_count(), 0);

        registry.record_audit(
            "audit-1".to_string(),
            "hash-1".to_string(),
            "LOW".to_string(),
            0, 0, 0, 1,
            1719000000,
        );
        assert_eq!(registry.get_audit_count(), 1);

        registry.record_audit(
            "audit-2".to_string(),
            "hash-2".to_string(),
            "CRITICAL".to_string(),
            3, 0, 0, 0,
            1719000001,
        );
        assert_eq!(registry.get_audit_count(), 2);
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
            "LOW".to_string(),
            0, 0, 0, 0,
            0,
        );
    }
}
