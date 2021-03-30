//
//  Modified version of AES-CTR-DRBG by Bassham & Lawrence.
//  Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
//  Rust implementation by K. Kwiatkowski. All rights reserved.
//
pub mod ctr {
	use crypto::aes;
	use crypto::buffer::{ RefReadBuffer, RefWriteBuffer, BufferResult };

	pub struct DrbgCtx{
	    pub reseed_counter: usize,
	    pub key: [u8;32],
	    pub ctr: [u8;16]
	}

	impl DrbgCtx {
	    const CTR_LEN: usize = 16;
	    const KEY_LEN: usize = 32;
	    pub const fn new() -> Self {
	        Self {
	            reseed_counter: 0,
	            key: [0; DrbgCtx::KEY_LEN],
	            ctr: [0; DrbgCtx::CTR_LEN]
	        }
	    }

	    fn inc(&mut self) {
	        for i in 0..16 {
	            let j = 15-i;
	            if self.ctr[j] == 0xFF {
	                self.ctr[j] = 0
	            } else {
	                self.ctr[j] = self.ctr[j] + 1;
	                break;
	            }
	        }
	    }

	    fn process_aes_block(&self, block: &mut [u8]) {
	        let mut e = aes::ecb_encryptor(
	                aes::KeySize::KeySize256,
	                &self.key,
	                crypto::blockmodes::NoPadding);
	        let mut r = RefReadBuffer::new(&self.ctr);
	        let mut w = RefWriteBuffer::new(block);
	        match e.encrypt(&mut r, &mut w, true).unwrap() {
	            BufferResult::BufferOverflow => panic!("Wrong implementation"),
	            BufferResult::BufferUnderflow => {}
	        }
	    }

	    fn update(&mut self, seed: &[u8]) {
	        let mut t = vec![0;48];

	        for i in 0..3 {
	            self.inc();
	            self.process_aes_block(&mut t[i*16..]);
	        }
	        for i in 0..seed.len() {
	            t[i] ^= seed[i];
	        }
	        for i in 0..32 {
	            self.key[i] = t[i];
	        }
	        for i in 32..48 {
	            self.ctr[i-32] = t[i];
	        }
	    }

	    pub fn init(&mut self, entropy: &[u8], diversifier: Vec<u8>) {
	        let mut m = vec![0;48];
	        for i in 0..48 {
	            m[i] = entropy[i];
	        }
	        if diversifier.len() >= 48 {
	            for i in 0..48 {
	                m[i] ^= diversifier[i];
	            }
	        }
	        self.key = [0; DrbgCtx::KEY_LEN];
	        self.ctr = [0; DrbgCtx::CTR_LEN];
	        self.update(m.as_slice());
	        self.reseed_counter = 1;
	    }

	    pub fn get_random(&mut self, data: &mut [u8]) {
	        let mut i = 0;
	        let mut b = vec![0; 16];
	        let mut l = data.len();

	        while l > 0 {
	            self.inc();
	            self.process_aes_block(&mut b);

	            if l > 15 {
	                for k in 0..16 {
	                    data[i+k] = b[k];
	                }
	                i += 16;
	                l -= 16;
	            } else {
	                for k in 0..l {
	                    data[i+k] = b[k];
	                }
	                l = 0;
	            }
	        }

	        self.update(Vec::new().as_slice());
	        self.reseed_counter = self.reseed_counter+1;
	    }
	}
}
