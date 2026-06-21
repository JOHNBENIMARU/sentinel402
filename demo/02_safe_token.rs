use odra::prelude::*;
use odra::{Address, Mapping, Var};

#[odra::module]
pub struct SafeToken {
    balances: Mapping<Address, U256>,
    owner: Var<Address>,
    total_supply: Var<U256>,
}

#[odra::module]
impl SafeToken {
    pub fn init(&mut self, initial_supply: U256) {
        let caller = self.env().caller();
        self.balances.set(&caller, initial_supply);
        self.total_supply.set(initial_supply);
        self.owner.set(caller);
    }

    pub fn transfer(&mut self, to: Address, amount: U256) {
        let caller = self.env().caller();
        let balance = self.balances.get(&caller).unwrap_or_default();
        assert!(balance >= amount, "Insufficient balance");
        self.balances.set(&caller, balance.checked_sub(amount).unwrap_or_revert());
        self.balances.set(&to, self.balances.get(&to).unwrap_or_default().checked_add(amount).unwrap_or_revert());
    }

    pub fn approve(&mut self, spender: Address, amount: U256) {
        let caller = self.env().caller();
        assert!(caller != Address::zero(), "Invalid caller");
    }

    pub fn balance_of(&self, addr: Address) -> U256 {
        self.balances.get(&addr).unwrap_or_default()
    }
}
