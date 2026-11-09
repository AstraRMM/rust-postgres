//! Pool identity.

use std::fmt;
use std::sync::Arc;

/// Identity of one lazily created pool in a [`PoolSet`](crate::PoolSet).
///
/// A pool is keyed by the realm and the database, role, credential and
/// configuration identities that determine what its sessions are allowed to
/// do. A new credential or configuration generation is a new key (and a new
/// pool); the superseded pool drains and is evicted once idle. Resource
/// routing changes inside a realm are *not* part of the key: the driver
/// selects nodes, the pool only owns client lifecycle.
///
/// The fields are opaque labels chosen by the realm layer (AST-2129). They
/// must not contain secrets: keys appear in logs and `Debug` output.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PoolKey {
    realm: Arc<str>,
    database: Arc<str>,
    role: Arc<str>,
    credential_generation: u64,
    config_generation: u64,
    discriminator: Option<Arc<str>>,
}

impl PoolKey {
    /// A key for `role` on `database` in `realm`, generation 0.
    pub fn new(realm: &str, database: &str, role: &str) -> PoolKey {
        PoolKey {
            realm: realm.into(),
            database: database.into(),
            role: role.into(),
            credential_generation: 0,
            config_generation: 0,
            discriminator: None,
        }
    }

    /// Sets the credential generation (password, client certificate).
    pub fn with_credential_generation(mut self, generation: u64) -> PoolKey {
        self.credential_generation = generation;
        self
    }

    /// Sets the configuration generation (session settings, limits,
    /// endpoint policy).
    pub fn with_config_generation(mut self, generation: u64) -> PoolKey {
        self.config_generation = generation;
        self
    }

    /// Adds a free-form discriminator, e.g. a workload class with its own
    /// limits.
    pub fn with_discriminator(mut self, discriminator: &str) -> PoolKey {
        self.discriminator = Some(discriminator.into());
        self
    }

    /// The realm label.
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// The database name.
    pub fn database(&self) -> &str {
        &self.database
    }

    /// The role name.
    pub fn role(&self) -> &str {
        &self.role
    }

    /// The credential generation.
    pub fn credential_generation(&self) -> u64 {
        self.credential_generation
    }

    /// The configuration generation.
    pub fn config_generation(&self) -> u64 {
        self.config_generation
    }

    /// The discriminator, if any.
    pub fn discriminator(&self) -> Option<&str> {
        self.discriminator.as_deref()
    }
}

impl fmt::Debug for PoolKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PoolKey({}/{}/{} cred#{} cfg#{}",
            self.realm,
            self.database,
            self.role,
            self.credential_generation,
            self.config_generation
        )?;
        if let Some(d) = &self.discriminator {
            write!(f, " {}", d)?;
        }
        f.write_str(")")
    }
}

impl fmt::Display for PoolKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}
