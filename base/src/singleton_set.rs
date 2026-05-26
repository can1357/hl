use std::any::type_name;
use std::collections::BTreeSet;

use parking_lot::Mutex;

static SINGLETONS: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

#[derive(Debug)]
pub struct SingletonSet {
    name: String,
    type_name: &'static str,
    used_random_suffix: bool,
}

impl SingletonSet {
    pub fn new<T>(name: &str) -> Self {
        let type_name = type_name::<T>();
        let key = singleton_key(type_name, name);
        let mut singletons = SINGLETONS.lock();

        if !singletons.insert(key) {
            drop(singletons);
            panic!("Singleton already created: {name}");
        }

        Self {
            name: name.to_owned(),
            type_name,
            used_random_suffix: false,
        }
    }

    pub fn new_with_random_suffix<T>(name: &str) -> Self {
        let type_name = type_name::<T>();
        let key = singleton_key(type_name, name);
        let mut singletons = SINGLETONS.lock();

        if singletons.insert(key) {
            drop(singletons);
            return Self {
                name: name.to_owned(),
                type_name,
                used_random_suffix: false,
            };
        }

        drop(singletons);

        let name = format!("_{}", rand::random::<u64>());
        let key = singleton_key(type_name, &name);
        let mut singletons = SINGLETONS.lock();

        if !singletons.insert(key) {
            drop(singletons);
            panic!("SingletonSet could not register {type_name}::{name}");
        }

        Self {
            name,
            type_name,
            used_random_suffix: true,
        }
    }

    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[inline]
    pub fn type_name(&self) -> &'static str {
        self.type_name
    }

    #[inline]
    pub fn used_random_suffix(&self) -> bool {
        self.used_random_suffix
    }
}

impl Drop for SingletonSet {
    fn drop(&mut self) {
        let key = singleton_key(self.type_name, &self.name);
        let mut singletons = SINGLETONS.lock();

        if !singletons.remove(&key) {
            drop(singletons);
            panic!("Singleton never created: {key}");
        }
    }
}

#[inline]
fn singleton_key(type_name: &str, name: &str) -> String {
    format!("{type_name}::{name}")
}
