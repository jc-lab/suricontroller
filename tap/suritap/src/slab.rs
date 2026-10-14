//! A small generational slab used for epoll tokens.

pub(crate) struct Slab<T> {
    slots: Vec<(u32, Option<T>)>,
    free: Vec<u32>,
    len: usize,
}

impl<T> Slab<T> {
    pub fn new() -> Self {
        Slab {
            slots: Vec::new(),
            free: Vec::new(),
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    /// Inserts a value, returning `(index, generation)`.
    pub fn insert(&mut self, v: T) -> (u32, u32) {
        self.len += 1;
        if let Some(i) = self.free.pop() {
            let slot = &mut self.slots[i as usize];
            slot.0 = slot.0.wrapping_add(1) & 0x00ff_ffff;
            slot.1 = Some(v);
            return (i, slot.0);
        }
        self.slots.push((0, Some(v)));
        ((self.slots.len() - 1) as u32, 0)
    }

    pub fn get_mut(&mut self, idx: u32, gen: u32) -> Option<&mut T> {
        match self.slots.get_mut(idx as usize) {
            Some((g, Some(v))) if *g == gen => Some(v),
            _ => None,
        }
    }

    pub fn by_index(&mut self, idx: usize) -> Option<&mut T> {
        self.slots.get_mut(idx).and_then(|s| s.1.as_mut())
    }

    pub fn remove(&mut self, idx: u32) -> Option<T> {
        let v = self.slots.get_mut(idx as usize)?.1.take()?;
        self.free.push(idx);
        self.len -= 1;
        Some(v)
    }

    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.slots.iter_mut().filter_map(|s| s.1.as_mut())
    }
}
