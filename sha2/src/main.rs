// output is dependent upon every bit in the input, cant reverse it

// Convert input to 32-bit

// Order the input to 32 bit (0x00000000) rows

// Round up input size to next multiple of 512 by:

// Appending a single bit '1', then:

// Add 0 bits until we are 64 bits away from the next multiple of 512

// With the last 64 bits, encode the length of the original length of the 
// input as 32 bit as a 64 bit binary representation

// Next we split this padded input into blocks of 512 bits

// Blocks are made up of 16 32 bit words (16 * 32 = 512) and can be expressed as 
// M_0 ^ (i) (0th word of ith block), M_1 ^ (i), ...

// We now iterate through each block one by one

use core::default::Default;
const BUFFER_SIZE: usize = 1024 * 16;
use std::env;
use std::io::{Read, Cursor};

// These values were obtained by taking the first 32 bits of the fractional
// parts of the square roots of the first 8 prime numbers.
// E.g. sqrt(2) =>  1.41421356237... => 0.41421356237... => 414213... => binary => hex => 0x6a09e667
const H: [u32; 8] = [
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19,
];

// These values were obtained by taking the first 32 bits of the fractional
// parts of the cube roots of the first 64 prime numbers. Same as above but cube roots.
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 
    0xe9b5dba5, 0x3956c25b, 0x59f111f1, 
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 
    0x12835b01, 0x243185be, 0x550c7dc3, 
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 
    0xc19bf174, 0xe49b69c1, 0xefbe4786, 
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 
    0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 
    0x06ca6351, 0x14292967, 0x27b70a85, 
    0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 
    0x650a7354, 0x766a0abb, 0x81c2c92e, 
    0x92722c85, 0xa2bfe8a1, 0xa81a664b, 
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 
    0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 
    0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 
    0x78a5636f, 0x84c87814, 0x8cc70208, 
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 
    0xc67178f2
];

pub struct Sha256 {
    state: [u32; 8],
    remaining: [u8; 64], // Storage for blocks not yet processed
    num_remaining: usize, // Number of remaining 512 bit blocks
    completed_data_blocks: u64, // Number of completed 512 bit data block
}

impl Default for Sha256 {
    fn default() -> Self {
        Self {
            state: H,
            completed_data_blocks: 0,
            remaining: [0u8; 64],
            num_remaining: 0,
        }
    }
}

impl Sha256 {
    pub fn with_state(state: [u32; 8]) -> Self {
        Self {
            state,
            completed_data_blocks: 0,
            remaining: [0u8; 64],
            num_remaining: 0,
        }
    }

    fn update_state(state: &mut [u32; 8], data: &[u8; 64]) {
        // Message Scheduling Array Initialization

        // Grabs first 16 W values for this block
        let mut w = [0; 64]; //Initialize an array of 64 zeros.
        for (w, d) in w.iter_mut().zip(data.iter().step_by(4)).take(16) {
            *w = u32::from_be_bytes(unsafe { *(d as *const u8 as *const [u8; 4]) });
        }

        // Set remainder of W values
        for i in 16..64 {

            // W_i = (W_i-16 + W_i-7 + Sigma_0(W_i-15) + Sigma_1(W_i-2)) % 2^32

            // Sigma_0(x: u32) -> right rotate x by 7, right rotate x by 18, shift x 3 right, then bitwise XOR
            // add by digits and mod 2. Note that XOR is the same as mod 2 operation.
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);

            // Sigma_1(x: u32) -> right rotate x by 17, right rotate x by 19, shift x 10 right, then bitwise XOR
            // add by digits and mod 2. Note that XOR is the same as mod 2 operation.
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);

            // Then we sum s0 and s1 with W_t-16 and W_t-7, and then mod by 2^32 to ensure we fit in 32 bits. Note that
            // Wrapping add is the same as mod by 2^num of bits.
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        // Initalize h with our current state values, which remember changes per block
        let mut h = *state;
        for i in 0..64 {
            // Note this is a different sigma function than before, there is no right shift only right rotations now
            // Sigma_0(a) -> right rotate x by 7, right rotate x by 18, shift x 3 right, then bitwise
            // add by digits and mod 2. Note that XOR is the same as mod 2 operation.
            let s0 = h[0].rotate_right(2) ^ h[0].rotate_right(13) ^ h[0].rotate_right(22);

            // Note this is a different sigma function than before, there is no right shift only right rotations now
            // Sigma_1(e) -> right rotate x by 7, right rotate x by 18, shift x 3 right, then bitwise
            // add by digits and mod 2. Note that XOR is the same as mod 2 operation.
            let s1 = h[4].rotate_right(6) ^ h[4].rotate_right(11) ^ h[4].rotate_right(25);

            // Ch(e, f, g) -> for every bit, if the bit of e is 0, take the bit of g as output,
            // if the bit of e is one, take the bit of f as output
            let ch = (h[4] & h[5]) ^ (!h[4] & h[6]);

            // Ma(a, b, c) -> Simply take majority of 0 or 1 by bit.
            let ma = (h[0] & h[1]) ^ (h[0] & h[2]) ^ (h[1] & h[2]);

            // t0 = (h + Sigma_1(e) + Ch(e, f, g) + K_0 + W_0) % 2^32 (aka wrap add)
            let t0 = h[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);

            // t1 = Sigma_0(s) + Ma(a, b, c) % 2^32 (aka wrap add)
            let t1 = s0.wrapping_add(ma);

            // Follows a set formula:
            // h = g
            // g = f
            // f = e
            // e = d + t1
            // d = c
            // c = b
            // b = a
            // a = t1 + t2
            h[7] = h[6];
            h[6] = h[5];
            h[5] = h[4];
            h[4] = h[3].wrapping_add(t0);
            h[3] = h[2];
            h[2] = h[1];
            h[1] = h[0];
            h[0] = t0.wrapping_add(t1);
        }

        // Update our state values, basically H_0^i = a + H_0^i-1, H_0^i = b + H_0^i-1, ... , H_7^i = h + H_7^i-1
        for (i, v) in state.iter_mut().enumerate() {
            *v = v.wrapping_add(h[i]);
        }
    }

    // Update the hash after clearing one 512 bit data block
    pub fn update(&mut self, data: &[u8]) {
        //Get size of the data
        let mut len = data.len();
        let mut offset = 0;

        // Check if we have a block >= 512 remaining, note that 64 * 8 (datatype for data parameter) = 512
        if self.num_remaining > 0 && self.num_remaining + len >= 64 {
            // Copy &data[..64 - self.num_remaining] into self.remaining[self.num_remaining..]
            // Essentially fill the remaining buffer with 512 bits if possible.
            self.remaining[self.num_remaining..].copy_from_slice(&data[..64 - self.num_remaining]);
            Self::update_state(&mut self.state, &self.remaining);
            self.completed_data_blocks += 1;
            offset = 64 - self.num_remaining;
            len -= offset;
            self.num_remaining = 0;
        }

        // Get remaining amount of full 512 (64 byte) blocks
        let data_blocks = len / 64;
        // Get the remainider of grouping by 1=512
        let remain = len % 64;
        for _ in 0..data_blocks {
            Self::update_state(&mut self.state, unsafe {
                &*(data.as_ptr().add(offset) as *const [u8; 64])
            });
            offset += 64;
        }
        self.completed_data_blocks += data_blocks as u64;

        // Place any remaining data into the remaining buffer
        if remain > 0 {
            self.remaining[self.num_remaining..self.num_remaining + remain]
                .copy_from_slice(&data[offset..]);
            self.num_remaining += remain;
        }
    }

    // Clean up and finish hashing the remaining data after grouping by 512 bits
    pub fn finish(mut self) -> [u8; 32] {
        let data_bits = self.completed_data_blocks * 512 + self.num_remaining as u64 * 8;
        let mut remaining = [0u8; 72]; // Add one extra byte for padding/length
        remaining[0] = 128;

        // If we have less than 56 bytes remaning pad up to 56 bytes (64 - 8)
        let offset = if self.num_remaining < 56 {
            56 - self.num_remaining
        } else { // Otherwise if we have 56 or more bytes,
            120 - self.num_remaining
        };

        remaining[offset..offset + 8].copy_from_slice(&data_bits.to_be_bytes());
        self.update(&remaining[..offset + 8]);

        for h in self.state.iter_mut() {
            *h = h.to_be();
        }
        unsafe { *(self.state.as_ptr() as *const [u8; 32]) }
    }
}

// ------------------------ Driver Code ------------------------ //

fn sha256<R: Read>(r: &mut R) -> [u8; 32] {

    let mut buffer = Vec::with_capacity(BUFFER_SIZE);
    unsafe { buffer.set_len(BUFFER_SIZE); }
    let mut sha: Sha256 = Sha256::default();
    let mut n: usize;
    while {
        n = r.read(buffer.as_mut()).unwrap();
        n > 0
    } { sha.update(&buffer[..n]); }
    sha.finish()
}

fn print_hashed_msg(sum: &[u8]) {
    for b in sum {
        print!("{:02x}", b);
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() == 2 {
        let message: &String = &args[1];
        let mut cursor: Cursor<&[u8]> = Cursor::new(message.as_bytes());
        print_hashed_msg(&sha256(&mut cursor));
    } else {
        println!("Usage: cargo run message_to_hash")
    }
}