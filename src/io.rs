use core::ops::{Deref, DerefMut};

use alloc::vec::Vec;

use crate::{DecodeError, DecodeResult};

pub struct SliceWriter<'a> {
    out: &'a mut [u8],
    cursor: usize,
}

impl<'a> SliceWriter<'a> {
    pub fn new(slice: &'a mut [u8]) -> Self {
        SliceWriter {
            out: slice,
            cursor: 0,
        }
    }

    pub fn write_repeated(&mut self, val: u8, repeats: usize) {
        self.out[self.cursor..self.cursor + repeats].fill(val);
        self.cursor += repeats;
    }

    pub fn write_u8(&mut self, val: u8) {
        self.out[self.cursor] = val;
        self.cursor += 1;
    }

    pub fn write_i8(&mut self, val: i8) {
        self.out[self.cursor] = val.to_le_bytes()[0];
        self.cursor += 1;
    }

    pub fn write_u16_le(&mut self, val: u16) {
        self.out[self.cursor..self.cursor + 2].copy_from_slice(&val.to_le_bytes());
        self.cursor += 2;
    }

    pub fn write_u32_le(&mut self, val: u32) {
        self.out[self.cursor..self.cursor + 4].copy_from_slice(&val.to_le_bytes());
        self.cursor += 4;
    }

    pub fn write_i16_le(&mut self, val: i16) {
        self.out[self.cursor..self.cursor + 2].copy_from_slice(&val.to_le_bytes());
        self.cursor += 2;
    }

    pub fn write_i32_le(&mut self, val: i32) {
        self.out[self.cursor..self.cursor + 4].copy_from_slice(&val.to_le_bytes());
        self.cursor += 4;
    }

    pub fn write_slice(&mut self, val: &[u8]) {
        self.out[self.cursor..self.cursor + val.len()].copy_from_slice(val);
        self.cursor += val.len();
    }

    pub fn write_c_str(&mut self, s: &str) {
        self.write_slice(s.as_bytes());
        self.write_u8(0);
    }

    pub fn remainder(&mut self) -> &mut [u8] {
        &mut self.out[self.cursor..]
    }

    pub fn advance(&mut self, by: usize) {
        self.cursor += by;
    }

    pub fn finish(self) -> &'a [u8] {
        &self.out[..self.cursor]
    }
}

pub trait TinyReadExt<'a> {
    fn read_u8(&mut self) -> DecodeResult<u8>;
    fn read_u16_le(&mut self) -> DecodeResult<u16>;
    fn read_u32_le(&mut self) -> DecodeResult<u32>;
    fn read_chunk<const N: usize>(&mut self) -> DecodeResult<&'a [u8; N]>;
    fn read_slice(&mut self, len: usize) -> DecodeResult<&'a [u8]>;
}

impl<'a> TinyReadExt<'a> for &'a [u8] {
    fn read_u8(&mut self) -> DecodeResult<u8> {
        self.split_off_first()
            .copied()
            .ok_or(DecodeError::UnexpectedEof)
    }

    fn read_u16_le(&mut self) -> DecodeResult<u16> {
        self.read_chunk::<2>().copied().map(u16::from_le_bytes)
    }

    fn read_u32_le(&mut self) -> DecodeResult<u32> {
        self.read_chunk::<4>().copied().map(u32::from_le_bytes)
    }

    fn read_chunk<const N: usize>(&mut self) -> DecodeResult<&'a [u8; N]> {
        let (chunk, rem) = self
            .split_first_chunk::<N>()
            .ok_or(DecodeError::UnexpectedEof)?;
        *self = rem;
        Ok(chunk)
    }

    fn read_slice(&mut self, len: usize) -> DecodeResult<&'a [u8]> {
        self.split_off(..len).ok_or(DecodeError::UnexpectedEof)
    }
}

pub trait ByteVecImpl: Deref<Target = [u8]> + DerefMut {
    fn resize(&mut self, len: usize, val: u8);
    fn truncate(&mut self, len: usize);
    fn clear(&mut self);
}

impl ByteVecImpl for Vec<u8> {
    fn resize(&mut self, len: usize, val: u8) {
        self.resize(len, val)
    }

    fn truncate(&mut self, len: usize) {
        self.truncate(len)
    }

    fn clear(&mut self) {
        self.clear();
    }
}

impl<'a> ByteVecImpl for bumpalo::collections::Vec<'a, u8> {
    fn resize(&mut self, len: usize, val: u8) {
        self.resize(len, val);
    }

    fn truncate(&mut self, len: usize) {
        self.truncate(len);
    }

    fn clear(&mut self) {
        self.clear();
    }
}

impl<'a, const N: usize> ByteVecImpl for heapless::Vec<u8, N> {
    fn resize(&mut self, len: usize, val: u8) {
        self.resize(len, val);
    }

    fn truncate(&mut self, len: usize) {
        self.truncate(len);
    }

    fn clear(&mut self) {
        self.clear();
    }
}
