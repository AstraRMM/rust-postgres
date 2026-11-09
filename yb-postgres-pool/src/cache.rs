//! Bounded prepared-statement cache, one per physical connection.

use std::collections::HashMap;
use yb_tokio_postgres::types::Type;
use yb_tokio_postgres::Statement;

struct Entry {
    types: Box<[Type]>,
    statement: Statement,
    last_used: u64,
}

/// Statements are valid only on the connection that prepared them, so the
/// cache lives in the pooled connection. The key is the SQL text plus the
/// explicit parameter types; the session identity (role, search path) is
/// fixed per pool and a session that changes it is retired rather than
/// reused, and a pool-wide epoch ([`Pool::invalidate_statements`]) clears
/// every connection's cache after schema changes.
///
/// [`Pool::invalidate_statements`]: crate::Pool::invalidate_statements
pub(crate) struct StatementCache {
    capacity: usize,
    /// SQL text -> one entry per distinct explicit parameter-type list.
    entries: HashMap<Box<str>, Vec<Entry>>,
    len: usize,
    clock: u64,
    epoch: u64,
}

pub(crate) enum Lookup {
    Hit(Statement),
    Miss,
}

impl StatementCache {
    pub(crate) fn new(capacity: usize, epoch: u64) -> StatementCache {
        StatementCache {
            capacity,
            entries: HashMap::new(),
            len: 0,
            clock: 0,
            epoch,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Drops every entry if the pool epoch moved. Returns whether it did.
    pub(crate) fn sync_epoch(&mut self, epoch: u64) -> bool {
        if self.epoch == epoch {
            return false;
        }
        self.epoch = epoch;
        self.clear() > 0
    }

    pub(crate) fn get(&mut self, sql: &str, types: &[Type]) -> Lookup {
        if self.capacity == 0 {
            return Lookup::Miss;
        }
        self.clock += 1;
        let clock = self.clock;
        match self
            .entries
            .get_mut(sql)
            .and_then(|v| v.iter_mut().find(|e| &*e.types == types))
        {
            Some(entry) => {
                entry.last_used = clock;
                Lookup::Hit(entry.statement.clone())
            }
            None => Lookup::Miss,
        }
    }

    /// Inserts, evicting the least recently used entries while full.
    /// Returns the number of evictions. Dropping an evicted statement sends
    /// `Close` to the server.
    pub(crate) fn insert(&mut self, sql: &str, types: &[Type], statement: Statement) -> u64 {
        if self.capacity == 0 {
            return 0;
        }
        self.clock += 1;
        let mut evicted = 0;
        while self.len >= self.capacity && self.evict_oldest() {
            evicted += 1;
        }
        let bucket = self.entries.entry(sql.into()).or_default();
        if let Some(existing) = bucket.iter_mut().find(|e| &*e.types == types) {
            existing.statement = statement;
            existing.last_used = self.clock;
            return evicted;
        }
        bucket.push(Entry {
            types: types.into(),
            statement,
            last_used: self.clock,
        });
        self.len += 1;
        evicted
    }

    fn evict_oldest(&mut self) -> bool {
        let oldest = self
            .entries
            .iter()
            .flat_map(|(sql, v)| {
                v.iter()
                    .enumerate()
                    .map(move |(i, e)| (e.last_used, sql, i))
            })
            .min_by_key(|(used, _, _)| *used)
            .map(|(_, sql, i)| (sql.clone(), i));
        let (sql, index) = match oldest {
            Some(found) => found,
            None => return false,
        };
        if let Some(bucket) = self.entries.get_mut(&sql) {
            bucket.swap_remove(index);
            if bucket.is_empty() {
                self.entries.remove(&sql);
            }
        }
        self.len -= 1;
        true
    }

    pub(crate) fn clear(&mut self) -> usize {
        let n = self.len;
        self.entries.clear();
        self.len = 0;
        n
    }
}
