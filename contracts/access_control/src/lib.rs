#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};
use kora_shared::{errors::KoraError, events, reentrancy::ReentrancyGuard};

// ── Storage Keys ─────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Admin,
    Paused,
    Role(Address),
}

// ── Role enum ─────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Role {
    Admin,
    Operator,
    Verifier,
    None,
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct AccessControlContract;

#[contractimpl]
impl AccessControlContract {
    /// Initialise the contract. Can only be called once.
    pub fn initialize(env: Env, admin: Address) -> Result<(), KoraError> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(KoraError::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Paused, &false);
        env.storage()
            .persistent()
            .set(&DataKey::Role(admin.clone()), &Role::Admin);
        Ok(())
    }

    // ── Protocol pause ────────────────────────────────────────────────────────

    /// Pause the entire protocol. Admin only.
    ///
    /// Returns `KoraError::ProtocolPaused` if already paused.
    pub fn pause(env: Env, admin: Address) -> Result<(), KoraError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;
        if env
            .storage()
            .instance()
            .get::<_, bool>(&DataKey::Paused)
            .unwrap_or(false)
        {
            return Err(KoraError::ProtocolPaused);
        }
        let _guard = ReentrancyGuard::new(&env)?;
        env.storage().instance().set(&DataKey::Paused, &true);
        events::protocol_paused(&env, &admin);
        Ok(())
    }

    /// Unpause the protocol. Admin only.
    ///
    /// Returns `KoraError::NotPaused` if the protocol is not currently paused.
    pub fn unpause(env: Env, admin: Address) -> Result<(), KoraError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;
        if !env
            .storage()
            .instance()
            .get::<_, bool>(&DataKey::Paused)
            .unwrap_or(false)
        {
            return Err(KoraError::NotPaused);
        }
        let _guard = ReentrancyGuard::new(&env)?;
        env.storage().instance().set(&DataKey::Paused, &false);
        events::protocol_unpaused(&env, &admin);
        Ok(())
    }

    // ── Role management ───────────────────────────────────────────────────────

    /// Assign a role to an address. Admin only.
    ///
    /// - Granting `Role::Admin` is forbidden; use `transfer_admin` instead.
    /// - Granting `Role::None` is rejected as a no-op to prevent accidents.
    pub fn grant_role(
        env: Env,
        admin: Address,
        target: Address,
        role: Role,
    ) -> Result<(), KoraError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;
        if role == Role::Admin {
            return Err(KoraError::Unauthorized);
        }
        if role == Role::None {
            return Err(KoraError::Unauthorized);
        }
        let _guard = ReentrancyGuard::new(&env)?;
        env.storage()
            .persistent()
            .set(&DataKey::Role(target.clone()), &role);
        env.events().publish(
            (symbol_short!("ROLE_GRT"),),
            (target, role),
        );
        Ok(())
    }

    /// Revoke a role from an address. Admin only.
    ///
    /// Revoking the admin's own role is forbidden.
    pub fn revoke_role(env: Env, admin: Address, target: Address) -> Result<(), KoraError> {
        admin.require_auth();
        Self::require_admin(&env, &admin)?;
        let current_role = env
            .storage()
            .persistent()
            .get::<_, Role>(&DataKey::Role(target.clone()))
            .unwrap_or(Role::None);
        if current_role == Role::Admin {
            return Err(KoraError::Unauthorized);
        }
        let _guard = ReentrancyGuard::new(&env)?;
        env.storage()
            .persistent()
            .set(&DataKey::Role(target.clone()), &Role::None);
        env.events().publish(
            (symbol_short!("ROLE_REV"),),
            target,
        );
        Ok(())
    }

    // ── Admin transfer ────────────────────────────────────────────────────────

    /// Transfer admin to a new address. Current admin must sign.
    ///
    /// Self-transfer is rejected to prevent accidental no-ops.
    pub fn transfer_admin(
        env: Env,
        current_admin: Address,
        new_admin: Address,
    ) -> Result<(), KoraError> {
        current_admin.require_auth();
        Self::require_admin(&env, &current_admin)?;
        if current_admin == new_admin {
            return Err(KoraError::InvalidAddress);
        }
        let _guard = ReentrancyGuard::new(&env)?;
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        env.storage()
            .persistent()
            .set(&DataKey::Role(new_admin.clone()), &Role::Admin);
        env.storage()
            .persistent()
            .set(&DataKey::Role(current_admin), &Role::None);
        events::admin_transferred(&env, &new_admin);
        Ok(())
    }

    // ── Views ─────────────────────────────────────────────────────────────────

    /// Returns `true` if the protocol is currently paused.
    pub fn is_paused(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false)
    }

    /// Returns the role assigned to `address`, or `Role::None` if unassigned.
    pub fn get_role(env: Env, address: Address) -> Role {
        env.storage()
            .persistent()
            .get(&DataKey::Role(address))
            .unwrap_or(Role::None)
    }

    /// Returns `true` if `address` holds the given `role`.
    pub fn has_role(env: Env, address: Address, role: Role) -> bool {
        let assigned: Role = env
            .storage()
            .persistent()
            .get(&DataKey::Role(address))
            .unwrap_or(Role::None);
        assigned == role
    }

    /// Returns the current admin address.
    pub fn get_admin(env: Env) -> Result<Address, KoraError> {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(KoraError::NotInitialized)
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn require_admin(env: &Env, caller: &Address) -> Result<(), KoraError> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(KoraError::NotInitialized)?;
        if &admin != caller {
            return Err(KoraError::NotAdmin);
        }
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Env};

    fn setup() -> (Env, Address, AccessControlContractClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, AccessControlContract);
        let client = AccessControlContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        client.initialize(&admin);
        (env, admin, client)
    }

    // ── Initialisation ────────────────────────────────────────────────────────

    #[test]
    fn test_initialize_success() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, AccessControlContract);
        let client = AccessControlContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        assert!(client.try_initialize(&admin).is_ok());
        assert_eq!(client.get_admin(), admin);
        assert_eq!(client.get_role(&admin), Role::Admin);
    }

    #[test]
    fn test_initialize_already_initialized() {
        let (env, admin, client) = setup();
        assert!(client.try_initialize(&admin).is_err());
    }

    // ── Pause / Unpause ───────────────────────────────────────────────────────

    #[test]
    fn test_pause_unpause() {
        let (_, admin, client) = setup();
        assert!(!client.is_paused());
        client.pause(&admin);
        assert!(client.is_paused());
        client.unpause(&admin);
        assert!(!client.is_paused());
    }

    #[test]
    fn test_pause_already_paused_returns_error() {
        let (_, admin, client) = setup();
        client.pause(&admin);
        let result = client.try_pause(&admin);
        assert!(result.is_err());
    }

    #[test]
    fn test_unpause_when_not_paused_returns_not_paused_error() {
        let (_, admin, client) = setup();
        // Protocol starts unpaused — unpause should fail with NotPaused
        let result = client.try_unpause(&admin);
        assert!(result.is_err());
    }

    #[test]
    fn test_non_admin_cannot_pause() {
        let (env, _admin, client) = setup();
        let stranger = Address::generate(&env);
        assert!(client.try_pause(&stranger).is_err());
    }

    // ── Role management ───────────────────────────────────────────────────────

    #[test]
    fn test_grant_revoke_role() {
        let (env, admin, client) = setup();
        let operator = Address::generate(&env);

        client.grant_role(&admin, &operator, &Role::Operator);
        assert_eq!(client.get_role(&operator), Role::Operator);
        assert!(client.has_role(&operator, &Role::Operator));

        client.revoke_role(&admin, &operator);
        assert_eq!(client.get_role(&operator), Role::None);
        assert!(!client.has_role(&operator, &Role::Operator));
    }

    #[test]
    fn test_grant_admin_role_rejected() {
        let (env, admin, client) = setup();
        let target = Address::generate(&env);
        assert!(client.try_grant_role(&admin, &target, &Role::Admin).is_err());
    }

    #[test]
    fn test_grant_none_role_rejected() {
        let (env, admin, client) = setup();
        let target = Address::generate(&env);
        assert!(client.try_grant_role(&admin, &target, &Role::None).is_err());
    }

    #[test]
    fn test_revoke_admin_role_rejected() {
        let (_, admin, client) = setup();
        // Trying to revoke the admin's own role must fail
        assert!(client.try_revoke_role(&admin, &admin).is_err());
    }

    #[test]
    fn test_non_admin_cannot_grant_role() {
        let (env, _admin, client) = setup();
        let stranger = Address::generate(&env);
        let target = Address::generate(&env);
        assert!(client.try_grant_role(&stranger, &target, &Role::Verifier).is_err());
    }

    #[test]
    fn test_multiple_role_assignments() {
        let (env, admin, client) = setup();
        let verifier1 = Address::generate(&env);
        let verifier2 = Address::generate(&env);
        let operator = Address::generate(&env);

        client.grant_role(&admin, &verifier1, &Role::Verifier);
        client.grant_role(&admin, &verifier2, &Role::Verifier);
        client.grant_role(&admin, &operator, &Role::Operator);

        assert_eq!(client.get_role(&verifier1), Role::Verifier);
        assert_eq!(client.get_role(&verifier2), Role::Verifier);
        assert_eq!(client.get_role(&operator), Role::Operator);
    }

    #[test]
    fn test_role_override() {
        let (env, admin, client) = setup();
        let user = Address::generate(&env);

        client.grant_role(&admin, &user, &Role::Operator);
        assert_eq!(client.get_role(&user), Role::Operator);

        client.grant_role(&admin, &user, &Role::Verifier);
        assert_eq!(client.get_role(&user), Role::Verifier);
    }

    // ── Admin transfer ────────────────────────────────────────────────────────

    #[test]
    fn test_transfer_admin() {
        let (env, admin, client) = setup();
        let new_admin = Address::generate(&env);

        client.transfer_admin(&admin, &new_admin);
        assert_eq!(client.get_admin(), new_admin);
        assert_eq!(client.get_role(&new_admin), Role::Admin);
        assert_eq!(client.get_role(&admin), Role::None);
    }

    #[test]
    fn test_transfer_admin_self_rejected() {
        let (_, admin, client) = setup();
        assert!(client.try_transfer_admin(&admin, &admin).is_err());
    }

    #[test]
    fn test_non_admin_cannot_transfer_admin() {
        let (env, _admin, client) = setup();
        let stranger = Address::generate(&env);
        let new_admin = Address::generate(&env);
        assert!(client.try_transfer_admin(&stranger, &new_admin).is_err());
    }

    // ── has_role view ─────────────────────────────────────────────────────────

    #[test]
    fn test_has_role_returns_false_for_unassigned() {
        let (env, _admin, client) = setup();
        let user = Address::generate(&env);
        assert!(!client.has_role(&user, &Role::Verifier));
        assert!(!client.has_role(&user, &Role::Operator));
    }

    #[test]
    fn test_has_role_returns_true_after_grant() {
        let (env, admin, client) = setup();
        let user = Address::generate(&env);
        client.grant_role(&admin, &user, &Role::Verifier);
        assert!(client.has_role(&user, &Role::Verifier));
        assert!(!client.has_role(&user, &Role::Operator));
    }
}
