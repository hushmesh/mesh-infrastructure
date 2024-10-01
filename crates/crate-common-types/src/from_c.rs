use alloc::string::ToString;
use alloc::vec::Vec;

use crate::MeshError;

/// Many of our functions which call C functions are just trying to fill a buffer.  They follow a
/// pattern of:
///  - Allocate a buffer (a Vec<u8>).
///  - Call a C function with a pointer to the buffer, its capacity, and a mutable pointer to
///    return the output size.
///  - Based on the return value, return a Vec on success or some error on failure.
/// vec_from_c provides a common pathway to "safely" get either the filled Vec<u8> or Error. Though
/// it is marked unsafe as it entirely the callers' duty to ensure the filler function makes proper
/// use of its arguments.
///
/// Into<Result<(), MeshError>> is implemented for HmcStatus to make most calls straightforward.
/// But, this function is made to be general over anything that can return such a result, like
/// sgx_enclave_sign.
///
/// # Safety
///
/// It is the caller's responsibility to ensure that `filler` either return Err or sets its CBuf
/// appropriately.
pub unsafe fn generic_vec_from_c<E, R, F>(buf_len: usize, filler: F) -> Result<Vec<u8>, E>
where
    R: Into<Result<(), E>>,
    F: FnOnce(CBuf) -> R,
{
    let mut buf = Vec::with_capacity(buf_len);
    let mut out_len: usize = 0;

    let cbuf = CBuf {
        ptr: buf.as_mut_ptr(),
        cap: buf.capacity(),
        out_len: &mut out_len,
    };

    match filler(cbuf).into() {
        Ok(()) => {
            assert!(out_len <= buf_len);
            buf.set_len(out_len);
            buf.shrink_to_fit();
            Ok(buf)
        }
        Err(err) => Err(err),
    }
}

/// Works similarly to generic_vec_from_c
///
/// # Safety
///
/// It is the caller's responsibility to ensure that `filler` either return Err or sets its CBuf
/// appropriately.
pub unsafe fn generic_vec2_from_c<E, R, F>(
    x_buf_len: usize,
    y_buf_len: usize,
    filler: F,
) -> Result<(Vec<u8>, Vec<u8>), E>
where
    R: Into<Result<(), E>>,
    F: FnOnce(CBuf, CBuf) -> R,
{
    let (mut x_buf, mut x_out_len) = (Vec::with_capacity(x_buf_len), 0);
    let (mut y_buf, mut y_out_len) = (Vec::with_capacity(y_buf_len), 0);

    // The indexes into bufs should be obviously valid, 0 and 1.  We'll have to rely on this until
    // `each_mut` is stabilized.
    let x_cbuf = CBuf {
        ptr: x_buf.as_mut_ptr(),
        cap: x_buf.capacity(),
        out_len: &mut x_out_len,
    };
    let y_cbuf = CBuf {
        ptr: y_buf.as_mut_ptr(),
        cap: y_buf.capacity(),
        out_len: &mut y_out_len,
    };

    match filler(x_cbuf, y_cbuf).into() {
        Ok(()) => {
            for (buf, out_len) in [(&mut x_buf, x_out_len), (&mut y_buf, y_out_len)] {
                assert!(out_len <= buf.capacity());
                buf.set_len(out_len);
                buf.shrink_to_fit();
            }
            Ok((x_buf, y_buf))
        }
        Err(err) => Err(err),
    }
}

pub struct CBuf<'b> {
    pub ptr: *mut u8,
    pub cap: usize,
    pub out_len: &'b mut usize,
}

pub trait CByteSlice {
    fn c_maybe_ptr(self) -> *const u8;
}

impl CByteSlice for &[u8] {
    fn c_maybe_ptr(self) -> *const u8 {
        if self.is_empty() {
            core::ptr::null()
        } else {
            self.as_ptr()
        }
    }
}

/// Creates a slice from the pointer and length, just like [`core::slice::from_raw_parts`], except
/// that its lifetime is bounded to the pointer variable.
///
/// # Safety
///
/// `ptr` must point to `len` valid `T`s and those must not be mutated while `ptr` is borrowed.
#[inline]
pub unsafe fn pessimistic_slice<T>(ptr: &*const T, len: usize) -> &[T] {
    core::slice::from_raw_parts(*ptr, len)
}

/// Same as [`pessimistic_slice, but mutable.
#[inline]
pub unsafe fn pessimistic_slice_mut<T>(ptr: &*mut T, len: usize) -> &mut [T] {
    core::slice::from_raw_parts_mut(*ptr, len)
}

pub struct CBufWriter<'p> {
    ptr: &'p *mut u8,
    capacity: usize,
    len: &'p mut usize,
}

impl<'p> CBufWriter<'p> {
    /// Create a CBufWriter.  To ensure the safety of operations made on the CBufWriter itself,
    /// there must be `capacity` bytes to write to at `ptr`. `*len` will be set to 0 upon creation
    /// and updated with each successful call to `write()`.
    ///
    /// # Safety
    ///
    /// `ptr` must point to `capacity` bytes that are otherwise not required to be immutable
    /// elsewhere.
    pub unsafe fn new(ptr: &'p *mut u8, capacity: usize, len: &'p mut usize) -> Self {
        *len = 0;
        Self { ptr, capacity, len }
    }

    /// Serialize an object to the buffer.  If the buffer runs out of capacity, BufferTooSmall will
    /// be returned; any other error from serde_cbor will be a ParserError.
    pub fn write_cbor(&mut self, v: &impl serde::Serialize) -> Result<(), MeshError> {
        let mut ser = self.cbor_serializer();
        v.serialize(&mut ser).map_err(Self::cbor_error)
    }

    /// Create a serde_cbor::Serializer through which any objects serialized will be written to the
    /// buffer.
    pub fn cbor_serializer<'w>(&'w mut self) -> CborSerializer<'w, 'p> {
        serde_cbor::Serializer::new(self).packed_format()
    }

    /// Converts any error produced by serde_cbor using a CBufWriter into a MeshError.
    /// Specifically, this means to identify the "scratch too small" error produced IFF the provided
    /// buffer is too small. All other errors become ParseError.
    pub fn cbor_error(err: serde_cbor::Error) -> MeshError {
        if err.is_scratch_too_small() {
            MeshError::BufferTooSmall
        } else {
            MeshError::ParseError(err.to_string())
        }
    }
}

impl core::fmt::Write for CBufWriter<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        if s.is_empty() {
            return Ok(());
        }

        let max_to_write = self.capacity - *self.len;
        if max_to_write == 0 {
            return Err(core::fmt::Error);
        }

        if s.len() <= max_to_write {
            unsafe {
                core::ptr::copy_nonoverlapping(s.as_ptr(), self.ptr.add(*self.len), s.len());
            }
            *self.len += s.len();
            Ok(())
        } else {
            // Write as much as possible...
            let substr = (0..=max_to_write)
                .rev()
                .find_map(|idx| s.get(..idx))
                .unwrap_or("");
            unsafe {
                core::ptr::copy_nonoverlapping(
                    substr.as_ptr(),
                    self.ptr.add(*self.len),
                    substr.len(),
                );
            }
            *self.len += substr.len();
            Err(core::fmt::Error)
        }
    }
}

type CborSerializer<'w, 'p> = serde_cbor::Serializer<&'w mut CBufWriter<'p>>;

impl serde_cbor::ser::Write for CBufWriter<'_> {
    type Error = serde_cbor::Error;

    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        if buf.is_empty() {
            return Ok(());
        }
        let final_len = (self.len.checked_add(buf.len())).expect("CBufWriter overflow");
        if final_len > self.capacity {
            return Err(serde_cbor::Error::scratch_too_small(self.capacity as u64));
        }
        unsafe {
            core::ptr::copy_nonoverlapping(buf.as_ptr(), self.ptr.add(*self.len), buf.len());
        }
        *self.len = final_len;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde::Serialize;

    use super::*;

    #[test]
    fn test_serialize_and_capacity_error() {
        let mut buf = [0u8; 10];
        let buf_ptr = buf.as_mut_ptr();

        {
            let mut len = 0;
            // Safety: buf and buf_ptr will be stable for the lifetime of the writer.
            let mut writer = unsafe { CBufWriter::new(&buf_ptr, buf.len(), &mut len) };

            const TOO_BIG: &str = "I'm a string for a non-empty body";

            let mut ser = writer.cbor_serializer();
            let err = TOO_BIG.serialize(&mut ser).unwrap_err();
            assert_eq!(MeshError::BufferTooSmall, CBufWriter::cbor_error(err));
            // This is asserting a bit of an implementation detail, though one which should be stable
            // with the serde Serializer interface and any reasonably implemented CBOR serializer.
            // The 2-byte CBOR type information for the String and its length will have been written
            // with one call to write(), and the BufferTooSmall error would have been returned on a
            // second call to write() with the String body itself.
            assert_eq!(len, 2);
        }

        {
            let mut len = 0;
            // Safety: buf and buf_ptr will be stable for the lifetime of the writer.
            let mut writer = unsafe { CBufWriter::new(&buf_ptr, buf.len(), &mut len) };

            const TINY: &str = "tiny";

            let mut ser = writer.cbor_serializer();
            TINY.serialize(&mut ser)
                .expect("A 4 byte String should fit into a 10 byte buffer");
            assert_eq!(len, 5); // 1:(string,4) + 4:"tiny"

            let out: &str = serde_cbor::from_slice(&buf[..len]).unwrap();
            assert_eq!(out, TINY);
        }
    }
}
