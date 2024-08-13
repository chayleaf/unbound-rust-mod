use std::{borrow::Borrow, collections::HashMap, hash::Hash};

use smallvec::{smallvec, SmallVec};

#[derive(Debug)]
pub enum PrefixSet<T> {
    Map(HashMap<T, PrefixSet<T>>),
    Leaf,
}

impl<T> Default for PrefixSet<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> PrefixSet<T> {
    pub fn new() -> Self {
        Self::Map(HashMap::new())
    }
}

impl<T: Hash + Eq> PrefixSet<T> {
    // returns whether its new
    pub fn insert(&mut self, val: impl IntoIterator<Item = T>) -> bool {
        match self {
            Self::Leaf => false,
            Self::Map(map) => {
                let mut it = val.into_iter();
                if let Some(k) = it.next() {
                    map.entry(k).or_default().insert(it)
                } else {
                    *self = Self::Leaf;
                    true
                }
            }
        }
    }
    pub fn contains<'a, Y>(&self, val: impl IntoIterator<Item = &'a Y>) -> bool
    where
        T: 'a + Borrow<Y>,
        Y: 'a + ?Sized + Eq + Hash,
    {
        match self {
            Self::Leaf => true,
            Self::Map(map) => {
                let mut it = val.into_iter();
                if let Some(k) = it.next() {
                    let Some(next) = map.get(k) else {
                        return false;
                    };
                    next.contains(it)
                } else {
                    true
                }
            }
        }
    }
    pub fn iter(&self) -> impl Iterator<Item = impl DoubleEndedIterator + Iterator<Item = &T>> {
        match self {
            Self::Leaf => Iter(SmallVec::new(), SmallVec::new()),
            Self::Map(map) => Iter(smallvec![map.iter()], smallvec![]),
        }
    }
}

struct Iter<'a, T>(
    SmallVec<[std::collections::hash_map::Iter<'a, T, PrefixSet<T>>; 9]>,
    SmallVec<[&'a T; 8]>,
);

impl<'a, T> Iterator for Iter<'a, T> {
    type Item = smallvec::IntoIter<[&'a T; 8]>;
    fn next(&mut self) -> Option<Self::Item> {
        while let Some(it) = self.0.last_mut() {
            let Some((k, v)) = it.next() else {
                self.0.pop();
                self.1.pop()?;
                continue;
            };
            self.1.push(k);
            match v {
                PrefixSet::Leaf => {
                    let ret = self.1.clone().into_iter();
                    self.1.pop();
                    return Some(ret);
                }
                PrefixSet::Map(m) => {
                    self.0.push(m.iter());
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::PrefixSet;

    #[test]
    fn test() {
        let mut tree = PrefixSet::<&str>::new();
        assert!(tree.insert(["a", "b", "c"]));
        assert!(tree.insert(["b", "c", "d"]));
        assert!(tree.insert(["a", "b"]));
        assert!(!tree.insert(["a", "b", "c"]));
        assert!(tree.contains([&"a", &"b", &"c"]));
        assert!(!tree.contains([&"a", &"c"]));
        let mut it = tree.iter();
        assert!(matches!(
            it.next()
                .unwrap()
                .into_iter()
                .copied()
                .collect::<String>()
                .as_str(),
            "ab" | "bcd"
        ));
        assert!(matches!(
            it.next()
                .unwrap()
                .into_iter()
                .copied()
                .collect::<String>()
                .as_str(),
            "ab" | "bcd"
        ));
    }
}
