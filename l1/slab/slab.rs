use core::ops::{Index, IndexMut};

#[derive(Clone, Debug)]
enum Entry<T> {
    Occupied(T),
    Vacant(usize),
}

#[derive(Clone, Debug)]
pub struct Slab<T> {
    entries: Vec<Entry<T>>,
    len: usize,
    next: usize,
}

impl<T> Default for Slab<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Slab<T> {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            len: 0,
            next: 0,
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
            len: 0,
            next: 0,
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.entries.capacity()
    }

    #[inline]
    pub fn next_key(&self) -> usize {
        self.next
    }

    #[inline]
    pub fn contains(&self, key: usize) -> bool {
        matches!(self.entries.get(key), Some(Entry::Occupied(_)))
    }

    #[inline]
    pub fn get(&self, key: usize) -> Option<&T> {
        match self.entries.get(key) {
            Some(Entry::Occupied(value)) => Some(value),
            _ => None,
        }
    }

    #[inline]
    pub fn get_mut(&mut self, key: usize) -> Option<&mut T> {
        match self.entries.get_mut(key) {
            Some(Entry::Occupied(value)) => Some(value),
            _ => None,
        }
    }

    pub fn reserve(&mut self, additional: usize) {
        self.entries.reserve(additional);
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.len = 0;
        self.next = 0;
    }

    pub fn insert(&mut self, value: T) -> usize {
        let key = self.next;
        self.insert_at(key, value);
        key
    }

    pub fn insert_at(&mut self, key: usize, value: T) {
        // The recovered monomorph increments the occupied count before checking the
        // target slot and uses a saturating add.  Appending grows the backing Vec
        // with minimum capacity 4 and then doubles on later growth.  Reuse requires
        // a vacant entry whose binary discriminant is 2 and whose next-link is at +8.
        self.len = self.len.saturating_add(1);

        if key == self.entries.len() {
            self.entries.push(Entry::Occupied(value));
            self.next = key + 1;
            return;
        }

        let next = match self.entries.get(key) {
            Some(Entry::Vacant(next)) => *next,
            _ => panic!("expected vacant entry {}", key),
        };

        self.entries[key] = Entry::Occupied(value);
        self.next = next;
    }

    pub fn try_remove(&mut self, key: usize) -> Option<T> {
        if !matches!(self.entries.get(key), Some(Entry::Occupied(_))) {
            return None;
        }

        let old = core::mem::replace(&mut self.entries[key], Entry::Vacant(self.next));
        self.next = key;
        self.len = self.len.saturating_sub(1);

        match old {
            Entry::Occupied(value) => Some(value),
            Entry::Vacant(_) => unreachable!(),
        }
    }

    pub fn remove(&mut self, key: usize) -> T {
        self.try_remove(key).unwrap_or_else(|| panic!("invalid key"))
    }

    pub fn iter(&self) -> impl Iterator<Item = (usize, &T)> {
        self.entries.iter().enumerate().filter_map(|(key, entry)| match entry {
            Entry::Occupied(value) => Some((key, value)),
            Entry::Vacant(_) => None,
        })
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (usize, &mut T)> {
        self.entries
            .iter_mut()
            .enumerate()
            .filter_map(|(key, entry)| match entry {
                Entry::Occupied(value) => Some((key, value)),
                Entry::Vacant(_) => None,
            })
    }

    pub fn retain<F>(&mut self, mut keep: F)
    where
        F: FnMut(usize, &mut T) -> bool,
    {
        for key in 0..self.entries.len() {
            let remove = match self.entries.get_mut(key) {
                Some(Entry::Occupied(value)) => !keep(key, value),
                _ => false,
            };

            if remove {
                let _ = self.try_remove(key);
            }
        }
    }

    #[inline]
    pub fn raw_entry_count(&self) -> usize {
        self.entries.len()
    }
}

impl<T> Index<usize> for Slab<T> {
    type Output = T;

    fn index(&self, key: usize) -> &Self::Output {
        self.get(key).unwrap_or_else(|| panic!("invalid key"))
    }
}

impl<T> IndexMut<usize> for Slab<T> {
    fn index_mut(&mut self, key: usize) -> &mut Self::Output {
        self.get_mut(key).unwrap_or_else(|| panic!("invalid key"))
    }
}
