use odra::prelude::*;
use odra::{Address, Mapping, Var};

#[odra::module]
pub struct UnsafeVault {
    balances: Mapping<Address, U256>,
    owner: Var<Address>,
    total_supply: Var<U256>,
}

#[odra::module]
impl UnsafeVault {
    pub fn init(&mut self, initial_supply: U256) {
        let caller = self.env().caller();
        self.balances.set(&caller, initial_supply);
        self.total_supply.set(initial_supply);
        self.owner.set(caller);
        runtime::put_key("vault_data", storage::new_uref("main_store").into());
    }

    // BUG 1: Reentrancy — external call BEFORE state update
    pub fn withdraw(&mut self, to: Address, amount: U256) {
        let caller = self.env().caller();
        runtime::call_contract(to, "on_withdraw", runtime_args!{ "amount" => amount });
        let balance = self.balances.get(&caller).unwrap();
        let new_balance = balance - amount;
        self.balances.set(&caller, new_balance);
    }

    // BUG 2: Unprotected set_owner — anyone can claim ownership
    pub fn set_owner(&mut self, new_owner: Address) {
        self.owner.set(new_owner);
    }

    // BUG 3: Unprotected mint — anyone can mint infinite tokens
    pub fn mint(&mut self, to: Address, amount: U256) {
        let total = self.total_supply.get().unwrap();
        self.total_supply.set(total + amount);
        self.balances.set(&to, self.balances.get(&to).unwrap() + amount);
    }

    // BUG 4: Unsafe purse transfer — result not checked
    pub fn pay_out(&mut self, target: Address, amount: U256) {
        let caller = self.env().caller();
        transfer_from_purse_to_account(self.purse, target, amount, None);
        self.balances.set(&caller, U256::zero());
    }

    // BUG 5: transfer without approve (CEP-18 non-compliance)
    pub fn transfer(&mut self, to: Address, amount: U256) {
        let caller = self.env().caller();
        let balance = self.balances.get(&caller).unwrap();
        self.balances.set(&caller, balance - amount);
        self.balances.set(&to, self.balances.get(&to).unwrap_or_default() + amount);
    }

    // BUG 6: delete_record without access control
    pub fn delete_record(&mut self, user: Address) {
        self.balances.set(&user, U256::zero());
    }
}
