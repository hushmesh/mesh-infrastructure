use alloc::vec::Vec;
use core::num::NonZeroU32;

use log::error;
use rand_core::Error;
use rand_core::RngCore;

use crate::hmc_generate_random;
use crate::HmcDataType;
use crate::HmcStatus;

const RNG_FAILURE_CODE: NonZeroU32 = unsafe { NonZeroU32::new_unchecked(1) };

pub struct HmcRng;

impl HmcRng {
    pub fn new() -> Self {
        Self
    }
}
impl RngCore for HmcRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if let Err(err) = self.try_fill_bytes(dest) {
            panic!("fill_bytes failed: {}", err);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        let mut output_len: usize = 0;
        let len = dest.len();
        let status = unsafe {
            hmc_generate_random(
                len,
                HmcDataType::Raw,
                dest.as_mut_ptr(),
                len,
                &mut output_len,
            )
        };
        if status == HmcStatus::Ok {
            if output_len != len {
                error!("hmc_generate_random failed: output_len != len");
                return Err(Error::from(RNG_FAILURE_CODE));
            }
            Ok(())
        } else {
            error!("hmc_generate_random failed");
            Err(Error::from(RNG_FAILURE_CODE))
        }
    }
}

pub struct TestHmcRng {
    data: Vec<u8>,
}

impl TestHmcRng {
    pub fn new() -> Self {
        const RND_DATA: &str = concat!(
"955a3f60a7f9da1ab9717f44eaf59171ff6de8c063f91c011db02070541a1ed433acfb4937fa6ae045c53c3d6c9f12a272e5c8a68bb576b2dd99fd77a4111967",
"1c84044edda87c9fee797386489e1d781943cd10f33d032b81421fb38a9b11608dee42d9554b251ebbc9df0e1aee5ffafe892c7895a687253c31c7cd8c941745",
"39a57770cefb1051ca74cb7a61099b368a38338f1f2dc5fc753cf457d653eddd09a6fedd8f67249053841281981e9602b3b5fa323b438a28f82543ed561391ac",
"b2a9f6007d25bb70a4b94d17eda161b73c4efa6891ddcfb03193c00501ee777ab79b75b8cc7d7119624e4ecd7adb74a0aae9cc34fecbaa025d660bfa73476ef9",
"e4acfae966a92f28dfe28927343b3849d27495dce46d9eeebb9d9221229d5dc988d53bf14fbb3f24710f4d9230c57a326e41368469763a2afa15f53811214c19",
"dfd53dc1a8d4870756bbcdc5309e495f3bdbd505b75f3a9d7293d87e9e40c0affd93c7a77357c15bfbf474353a214a4761b5b50d3ff1ba76ea27b251ecf95224",
"b5ef753750c4ba1266ca35feefc5b4db8085083b6dc6d0f7edaf142aa11b1ef9450260b7ddd12a1b61f3e464065d2e8aaa4b6b950821797911644d6d4f887972",
"dca13ae5ca2e749e3ea75a05b0686e41def1c5fa9346db7a7fc8678344df9abdd30eaf80454bf284a130b84b40bea3c945a65b5a2482123a05e7510acb7787ee",
"8bbdbdb9fb27552cf92e0e72bfda0e44509cb0531a529201a1c78d0b8fe4d5bcccf784a9a8dd1b24fce8c78250887e632a5a70eba343e7c2c7f7e3ca0c79cb80",
"29b148f2abaa71c6de61cbd398e0ff3608a33a558468746cc689f0b8f6a099ca9cab63646b7c7e415bd1d551864f1d94c3977bb61350cc063211a51d6a308b35",
"955a3f60a7f9da1ab9717f44eaf59171ff6de8c063f91c011db02070541a1ed433acfb4937fa6ae045c53c3d6c9f12a272e5c8a68bb576b2dd99fd77a4111967",
"1c84044edda87c9fee797386489e1d781943cd10f33d032b81421fb38a9b11608dee42d9554b251ebbc9df0e1aee5ffafe892c7895a687253c31c7cd8c941745",
"39a57770cefb1051ca74cb7a61099b368a38338f1f2dc5fc753cf457d653eddd09a6fedd8f67249053841281981e9602b3b5fa323b438a28f82543ed561391ac",
"b2a9f6007d25bb70a4b94d17eda161b73c4efa6891ddcfb03193c00501ee777ab79b75b8cc7d7119624e4ecd7adb74a0aae9cc34fecbaa025d660bfa73476ef9",
"e4acfae966a92f28dfe28927343b3849d27495dce46d9eeebb9d9221229d5dc988d53bf14fbb3f24710f4d9230c57a326e41368469763a2afa15f53811214c19",
"dfd53dc1a8d4870756bbcdc5309e495f3bdbd505b75f3a9d7293d87e9e40c0affd93c7a77357c15bfbf474353a214a4761b5b50d3ff1ba76ea27b251ecf95224",
"b5ef753750c4ba1266ca35feefc5b4db8085083b6dc6d0f7edaf142aa11b1ef9450260b7ddd12a1b61f3e464065d2e8aaa4b6b950821797911644d6d4f887972",
"dca13ae5ca2e749e3ea75a05b0686e41def1c5fa9346db7a7fc8678344df9abdd30eaf80454bf284a130b84b40bea3c945a65b5a2482123a05e7510acb7787ee",
"8bbdbdb9fb27552cf92e0e72bfda0e44509cb0531a529201a1c78d0b8fe4d5bcccf784a9a8dd1b24fce8c78250887e632a5a70eba343e7c2c7f7e3ca0c79cb80",
"29b148f2abaa71c6de61cbd398e0ff3608a33a558468746cc689f0b8f6a099ca9cab63646b7c7e415bd1d551864f1d94c3977bb61350cc063211a51d6a308b35");
        let data: Vec<u8> = (0..RND_DATA.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&RND_DATA[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
            .expect("Failed to parse RND_DATA");
        Self { data }
    }
}

impl RngCore for TestHmcRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if let Err(err) = self.try_fill_bytes(dest) {
            panic!("fill_bytes failed: {}", err);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        let len = dest.len();
        if len > self.data.len() {
            return Err(Error::from(RNG_FAILURE_CODE));
        }
        dest.copy_from_slice(&self.data[0..len]);
        self.data.drain(0..len);
        Ok(())
    }
}
