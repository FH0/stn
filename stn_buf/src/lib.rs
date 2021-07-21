use std::slice;

pub trait VecBuf {
    unsafe fn remain_mut(&mut self) -> &mut [u8];
    unsafe fn add_len(&mut self, len: usize);
}

impl VecBuf for Vec<u8> {
    unsafe fn remain_mut(&mut self) -> &mut [u8] {
        slice::from_raw_parts_mut(
            self.as_mut_ptr().add(self.len()) as *mut u8,
            self.capacity() - self.len(),
        )
    }

    unsafe fn add_len(&mut self, len: usize) {
        self.set_len(self.len() + len)
    }
}
