pub struct Batch<T> {
    pub items: Vec<T>,
    pub batch_size: usize,
}

impl<T> Batch<T> {
    pub fn new(batch_size: usize) -> Self {
        Self {
            items: Vec::new(),
            batch_size,
        }
    }

    pub fn add(&mut self, item: T) {
        self.items.push(item);
    }

    pub fn is_full(&self) -> bool {
        self.items.len() >= self.batch_size
    }
}
