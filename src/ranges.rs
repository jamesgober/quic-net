//! A set of `u64` ranges kept sorted, disjoint, and not touching: what
//! arrived of a stream, what is waiting to be sent, what was acknowledged.

use core::ops::Range;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct RangeSet {
    r: Vec<Range<u64>>,
}

impl RangeSet {
    pub(crate) fn new() -> RangeSet {
        RangeSet { r: Vec::new() }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.r.is_empty()
    }

    pub(crate) fn first(&self) -> Option<&Range<u64>> {
        self.r.first()
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &Range<u64>> {
        self.r.iter()
    }

    /// The ranges ending after `v`, in order.
    pub(crate) fn iter_from(&self, v: u64) -> impl Iterator<Item = &Range<u64>> {
        let i = self.r.partition_point(|y| y.end <= v);
        self.r[i..].iter()
    }

    /// How many ranges there would be after inserting `x`.
    pub(crate) fn len_after_insert(&self, x: &Range<u64>) -> usize {
        if x.start >= x.end {
            return self.r.len();
        }
        let i = self.r.partition_point(|y| y.end < x.start);
        let j = self.r.partition_point(|y| y.start <= x.end);
        self.r.len() + 1 - j.saturating_sub(i)
    }

    pub(crate) fn clear(&mut self) {
        self.r.clear();
    }

    /// Adds `x`, merging with every range it overlaps or touches.
    pub(crate) fn insert(&mut self, x: Range<u64>) {
        if x.start >= x.end {
            return;
        }
        let i = self.r.partition_point(|y| y.end < x.start);
        let (mut s, mut e) = (x.start, x.end);
        let mut j = i;
        while j < self.r.len() && self.r[j].start <= e {
            s = s.min(self.r[j].start);
            e = e.max(self.r[j].end);
            j += 1;
        }
        self.r.splice(i..j, core::iter::once(s..e));
    }

    /// Takes `x` out, splitting a range it falls inside.
    pub(crate) fn remove(&mut self, x: Range<u64>) {
        if x.start >= x.end {
            return;
        }
        let i = self.r.partition_point(|y| y.end <= x.start);
        let mut j = i;
        let mut keep: [Option<Range<u64>>; 2] = [None, None];
        while j < self.r.len() && self.r[j].start < x.end {
            let y = &self.r[j];
            if y.start < x.start {
                keep[0] = Some(y.start..x.start);
            }
            if y.end > x.end {
                keep[1] = Some(x.end..y.end);
            }
            j += 1;
        }
        self.r.splice(i..j, keep.into_iter().flatten());
    }

    /// Whether every value of `x` is in the set.
    pub(crate) fn covers(&self, x: Range<u64>) -> bool {
        if x.start >= x.end {
            return true;
        }
        let i = self.r.partition_point(|y| y.end <= x.start);
        self.r
            .get(i)
            .is_some_and(|y| y.start <= x.start && y.end >= x.end)
    }

    /// Drops everything below `v`.
    pub(crate) fn remove_below(&mut self, v: u64) {
        self.remove(0..v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn model(s: &RangeSet) -> BTreeSet<u64> {
        s.iter().flat_map(|r| r.clone()).collect()
    }

    #[test]
    fn test_against_a_model() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..200 {
            let mut s = RangeSet::new();
            let mut m = BTreeSet::new();
            for _ in 0..60 {
                let a = next() % 200;
                let b = a + next() % 20;
                if next() % 3 == 0 {
                    s.remove(a..b);
                    for v in a..b {
                        m.remove(&v);
                    }
                } else {
                    s.insert(a..b);
                    m.extend(a..b);
                }
                assert_eq!(model(&s), m);
                // Sorted, disjoint, not touching, none empty.
                for w in s.r.windows(2) {
                    assert!(w[0].end < w[1].start, "{:?}", s.r);
                }
                assert!(s.iter().all(|r| r.start < r.end));
                let c = next() % 200;
                let d = c + next() % 10;
                assert_eq!(s.covers(c..d), (c..d).all(|v| m.contains(&v)));
                let mut t = s.clone();
                let predicted = t.len_after_insert(&(c..d));
                t.insert(c..d);
                assert_eq!(predicted, t.r.len(), "{:?} + {c}..{d}", s.r);
                let from: Vec<_> = s.iter_from(c).cloned().collect();
                let want: Vec<_> = s.iter().filter(|r| r.end > c).cloned().collect();
                assert_eq!(from, want);
            }
        }
    }

    #[test]
    fn test_edges() {
        let mut s = RangeSet::new();
        s.insert(5..5);
        assert!(s.is_empty());
        s.insert(0..10);
        s.insert(10..20);
        assert_eq!(s.r.len(), 1);
        s.remove(5..15);
        assert_eq!(s.r, vec![0..5, 15..20]);
        s.remove_below(3);
        assert_eq!(s.r, vec![3..5, 15..20]);
        assert!(s.covers(7..7));
        s.clear();
        assert!(s.first().is_none());
    }
}
