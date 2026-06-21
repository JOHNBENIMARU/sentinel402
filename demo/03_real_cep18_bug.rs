use odra::prelude::*;
use odra::{Address, Mapping, Var};

#[odra::module]
pub struct MyToken {
    balances: Mapping<Address, U256>,
    allowances: Mapping<(Address, Address), U256>,
    total_supply: Var<U256>,
}

#[odra::module]
impl MyToken {
    pub fn init(&mut self, supply: U256) {
        let caller = self.env().caller();
        self.balances.set(&caller, supply);
        self.total_supply.set(supply);
    }

    pub fn transfer(&mut self, to: Address, amount: U256) {
        let caller = self.env().caller();
        let balance = self.balances.get(&caller).unwrap_or_default();
        assert!(balance >= amount, "Insufficient");
        self.balances.set(&caller, balance - amount);
        self.balances.set(&to, self.balances.get(&to).unwrap_or_default() + amount);
    }

    // BUG: transfer_from doesn't deduct allowance!
    pub fn transfer_from(&mut self, from: Address, to: Address, amount: U256) {
        let balance = self.balances.get(&from).unwrap_or_default();
        self.balances.set(&from, balance - amount);
        self.balances.set(&to, self.balances.get(&to).unwrap_or_default() + amount);
        // Missing: self.allowances.set(&(from, caller), allowance - amount);
    }

    pub fn approve(&mut self, spender: Address, amount: U256) {
        let caller = self.env().caller();
        self.allowances.set(&(caller, spender), amount);
    }

    // BUG: mint is unprotected
    pub fn mint(&mut self, to: Address, amount: U256) {
        let total = self.total_supply.get().unwrap_or_default();
        self.total_supply.set(total + amount);
        self.balances.set(&to, self.balances.get(&to).unwrap_or_default() + amount);
    }
}
