use std::{
    ops::{Bound, RangeBounds},
    ptr,
};

#[derive(Clone, Debug)]
pub struct Buf {
    buf: Box<[u8]>,
    len: usize,
}

impl Buf {
    pub fn new(capacity: usize) -> Self {
        Self {
            buf: vec![0u8; capacity].into_boxed_slice(),
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn add_len(&mut self, len: usize) {
        self.len += len;
    }

    pub fn get_used(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    pub fn get_used_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.len]
    }

    /// write only
    pub unsafe fn get_unused(&mut self) -> &mut [u8] {
        &mut self.buf[self.len..]
    }

    pub fn drain<R>(&mut self, range: R)
    where
        R: RangeBounds<usize>,
    {
        let start = match range.start_bound() {
            Bound::Unbounded => 0,
            Bound::Included(&n) => n,
            Bound::Excluded(&n) => n.saturating_add(1),
        };
        let end = match range.end_bound() {
            Bound::Unbounded => self.len,
            Bound::Included(&n) => n.saturating_add(1),
            Bound::Excluded(&n) => n,
        };

        assert!(start <= end, "start({}) <= end({})", start, end);
        assert!(end <= self.len, "end({}) <= self.len({})", end, self.len);

        unsafe {
            ptr::copy(
                self.buf.as_ptr().offset(end as _),
                self.buf.as_mut_ptr().offset(start as _),
                self.len - end,
            );
        }
        self.len -= end - start;
    }
}

#[test]
fn t1() {
    use std::io::Write;

    let mut buf = Buf::new(10);

    let nwrite = unsafe { buf.get_unused() }.write(&[1, 1, 1]).unwrap();
    buf.add_len(nwrite);
    assert!(buf.get_used() == &[1, 1, 1]);

    buf.drain(1..3);
    assert!(buf.get_used() == &[1]);

    let nwrite = unsafe { buf.get_unused() }.write(&[1, 1, 1]).unwrap();
    buf.add_len(nwrite);
    assert!(buf.get_used() == &[1]);

    buf.drain(..);
    assert!(buf.get_used() == &[]);
}
