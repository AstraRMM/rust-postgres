//! Pool identity.

use std::fmt;
use std::sync::Arc;
use yb_tokio_postgres::realm::Realm;

/// Identity of one lazily created pool in a [`PoolSet`](crate::PoolSet).
///
/// A pool is keyed by the realm and the database, role, credential and
/// configuration identities that determine what its sessions are allowed to
/// do. A new credential or configuration generation is a new key (and a new
/// pool); when the set creates it, pools of older generations of the same
/// identity are retired once the new one has warmed. Resource
/// routing changes inside a realm are *not* part of the key: the driver
/// selects nodes, the pool only owns client lifecycle.
///
/// The fields are opaque labels chosen by the realm layer (AST-2129). They
/// must not contain secrets: keys appear in logs and `Debug` output.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PoolKey {
    realm: Arc<str>,
    incarnation: Option<Arc<str>>,
    database: Arc<str>,
    role: Arc<str>,
    credential_generation: u64,
    config_generation: u64,
    discriminator: Option<Arc<str>>,
}

impl PoolKey {
    /// A key for `role` on `database` in the realm named `realm`,
    /// generation 0.
    pub fn new(realm: &str, database: &str, role: &str) -> PoolKey {
        PoolKey {
            realm: realm.into(),
            incarnation: None,
            database: database.into(),
            role: role.into(),
            credential_generation: 0,
            config_generation: 0,
            discriminator: None,
        }
    }

    /// A key for `role` on `database` in `realm`, carrying the realm's name
    /// and declared cluster incarnation ([`Realm::key`]). Pass the same
    /// `Realm` to the spec's `Config::realm` so the driver's topology and
    /// node accounting are the realm's own.
    pub fn for_realm(realm: &Realm, database: &str, role: &str) -> PoolKey {
        let mut key = PoolKey::new(realm.key().name(), database, role);
        key.incarnation = realm.key().incarnation().map(Into::into);
        key
    }

    /// Sets the cluster incarnation label.
    pub fn with_incarnation(mut self, incarnation: &str) -> PoolKey {
        self.incarnation = Some(incarnation.into());
        self
    }

    /// The cluster incarnation, if declared.
    pub fn incarnation(&self) -> Option<&str> {
        self.incarnation.as_deref()
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

    /// The key with both generations reset: what generations of one
    /// identity share.
    pub(crate) fn identity(&self) -> PoolKey {
        let mut identity = self.clone();
        identity.credential_generation = 0;
        identity.config_generation = 0;
        identity
    }

    /// Whether `self` is a newer generation of the same realm, incarnation,
    /// database, role and discriminator as `older`: neither generation is
    /// lower and at least one is higher.
    pub fn supersedes(&self, older: &PoolKey) -> bool {
        self.realm == older.realm
            && self.incarnation == older.incarnation
            && self.database == older.database
            && self.role == older.role
            && self.discriminator == older.discriminator
            && self.credential_generation >= older.credential_generation
            && self.config_generation >= older.config_generation
            && (self.credential_generation, self.config_generation)
                != (older.credential_generation, older.config_generation)
    }
}

impl fmt::Debug for PoolKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PoolKey({}", self.realm)?;
        if let Some(incarnation) = &self.incarnation {
            write!(f, "@{}", incarnation)?;
        }
        write!(
            f,
            "/{}/{} cred#{} cfg#{}",
            self.database, self.role, self.credential_generation, self.config_generation
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
