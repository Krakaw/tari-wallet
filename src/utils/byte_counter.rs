use std::io;

#[derive(Debug, Clone, Default)]
pub struct ByteCounter {
    count: usize,
}

impl ByteCounter {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn get(&self) -> usize {
        self.count
    }
}

impl io::Write for ByteCounter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = buf.len();
        self.count += len;
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
