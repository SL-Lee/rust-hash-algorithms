// Translated to Rust from https://github.com/XKCP/XKCP/blob/master/Standalone/CompactFIPS202/Python/CompactFIPS202.py

use std::cmp::min;
use std::convert::TryInto;

pub fn keccak(
    rate: usize,
    capacity: usize,
    input_bytes: &[u8],
    delimited_suffix: u8,
    mut output_bytes_len: usize,
) -> Option<Vec<u8>> {
    let mut output_bytes = Vec::with_capacity(output_bytes_len);
    let mut state = vec![0; 200];
    let rate_in_bytes = rate / 8;
    let mut block_size = 0;

    if rate + capacity != 1600 || rate % 8 != 0 {
        return None;
    }

    let mut input_offset = 0;

    // Absorb all the input blocks
    while input_offset < input_bytes.len() {
        block_size = min(input_bytes.len() - input_offset, rate_in_bytes);

        for i in 0..block_size {
            state[i] ^= input_bytes[i + input_offset];
        }

        input_offset += block_size;

        if block_size == rate_in_bytes {
            keccak_f1600(&mut state);
            block_size = 0;
        }
    }

    // Do the padding and switch to the squeezing phase
    state[block_size] ^= delimited_suffix;

    if delimited_suffix & 0x80 != 0 && block_size == (rate_in_bytes - 1) {
        keccak_f1600(&mut state);
    }

    state[rate_in_bytes - 1] ^= 0x80;
    keccak_f1600(&mut state);

    // Squeeze out all the output blocks
    while output_bytes_len > 0 {
        block_size = min(output_bytes_len, rate_in_bytes);
        output_bytes.extend(&state[0..block_size]);
        output_bytes_len -= block_size;

        if output_bytes_len > 0 {
            keccak_f1600(&mut state);
        }
    }

    Some(output_bytes)
}

fn keccak_f1600(state: &mut Vec<u8>) {
    let mut lanes = (0..5)
        .map(|x| {
            (0..5)
                .map(|y| {
                    u64::from_le_bytes(
                        state[8 * (x + 5 * y)..8 * (x + 5 * y) + 8]
                            .try_into()
                            .unwrap(),
                    )
                })
                .collect::<Vec<u64>>()
        })
        .collect::<Vec<Vec<u64>>>();
    keccak_f1600_permutate(&mut lanes);

    for x in 0..5 {
        for y in 0..5 {
            for (i, &z) in lanes[x][y].to_le_bytes().iter().enumerate() {
                state[8 * (x + 5 * y) + i] = z;
            }
        }
    }
}

#[allow(clippy::many_single_char_names)]
fn keccak_f1600_permutate(lanes: &mut Vec<Vec<u64>>) {
    let mut r = 1;

    for _ in 0..24 {
        // θ
        let c = (0..5)
            .map(|x| {
                lanes[x][0]
                    ^ lanes[x][1]
                    ^ lanes[x][2]
                    ^ lanes[x][3]
                    ^ lanes[x][4]
            })
            .collect::<Vec<u64>>();
        let d = (0..5)
            .map(|x| c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1))
            .collect::<Vec<u64>>();

        for x in 0..5 {
            for y in 0..5 {
                lanes[x][y] ^= d[x];
            }
        }

        // ρ and π
        let (mut x, mut y) = (1, 0);
        let mut current = lanes[x][y];

        for t in 0..24 {
            let temp = x;
            x = y;
            y = (2 * temp + 3 * y) % 5;
            let temp = current;
            current = lanes[x][y];
            lanes[x][y] = temp.rotate_left((t + 1) * (t + 2) / 2);
        }

        // χ
        for y in 0..5 {
            let t = (0..5).map(|x| lanes[x][y]).collect::<Vec<u64>>();

            for x in 0..5 {
                lanes[x][y] = t[x] ^ ((!t[(x + 1) % 5]) & t[(x + 2) % 5]);
            }
        }

        // ι
        for j in 0..7 {
            r = ((r << 1) ^ ((r >> 7) * 0x71)) % 256;

            if r & 2 != 0 {
                lanes[0][0] ^= 1 << ((1 << j) - 1);
            }
        }
    }
}
