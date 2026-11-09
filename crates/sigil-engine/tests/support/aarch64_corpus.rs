//! Exact ADR-017 corpus: seed 0x48c0ffee, 1,103,289 visits.
fn step(s: &mut u64) -> u32 {
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    *s as u32
}
const BASES: &[u32] = &[
    0x14000000, 0x94000000, 0x54000000, 0x34000000, 0xb5000000, 0x36000000, 0xb7000000, 0xd61f0000,
    0xd63f0000, 0xd65f0000, 0x10000000, 0x90000000, 0x12800000, 0x52800000, 0x72800000, 0x92800000,
    0xd2800000, 0xf2800000, 0x2a0003e0, 0xaa0003e0, 0x11000000, 0x51000000, 0x91000000, 0xd1000000,
    0xb9400000, 0xf9400000, 0xb9000000, 0xf9000000, 0x28800000, 0x28c00000, 0x29000000, 0x29400000,
    0x29800000, 0x29c00000, 0xa8800000, 0xa8c00000, 0xa9000000, 0xa9400000, 0xa9800000, 0xa9c00000,
    0xd503201f, 0xd503233f, 0xd503245f, 0xd503249f, 0xd50324df, 0xd65f0bff, 0, 0xffffffff,
];
pub fn corpus(mut visit: impl FnMut(u32)) {
    // Explicit masks' bit boundaries, ZR/SP, register-width, displacement and shift extremes.
    for &b in BASES {
        visit(b);
        for bit in 0..32 {
            visit(b ^ (1 << bit));
        }
        for fields in [
            0x1f, 0x3e0, 0x7c00, 0x1f0000, 0x003fffff, 0x03ffffff, 0x80000000, 0x7fffffff,
            0xffffffff,
        ] {
            visit(b | fields);
            visit(b & !fields);
        }
    }
    // Exact sign-bit boundaries and adjacent values for every immediate family.
    for b in [0x14000000, 0x94000000] {
        for imm in [0, 1, 0x1fffffe, 0x1ffffff, 0x2000000, 0x2000001, 0x3ffffff] {
            visit(b | imm);
        }
    }
    for b in [0x54000000, 0x34000000, 0xb5000000] {
        for imm in [0, 1, 0x3ffff, 0x40000, 0x7ffff] {
            visit(b | (imm << 5));
        }
    }
    for b in [0x36000000, 0xb7000000] {
        for imm in [0, 1, 0x1fff, 0x2000, 0x3fff] {
            visit(b | (imm << 5));
        }
    }
    for b in [0x10000000, 0x90000000] {
        for imm in [0, 1, 0xfffff, 0x100000, 0x1fffff] {
            visit(b | ((imm & 3) << 29) | ((imm >> 2) << 5));
        }
    }
    for b in [
        0x12800000, 0x52800000, 0x72800000, 0x92800000, 0xd2800000, 0xf2800000,
    ] {
        for hw in 0..4 {
            for imm in [0, 1, 0x7fff, 0x8000, 0xffff] {
                for rd in [0, 30, 31] {
                    visit(b | (hw << 21) | (imm << 5) | rd);
                }
            }
        }
    }
    for &b in BASES {
        for rd in [0, 30, 31] {
            for rn in [0, 30, 31] {
                visit(b | rd | (rn << 5));
            }
        }
    }
    let mut state = 0x48c0ffeeu64;
    for _ in 0..1_000_000 {
        visit(step(&mut state));
    }
    // Structured hostile mutations increase exercised eligible instructions beyond uniform noise.
    for i in 0..100_000 {
        let b = BASES[i % BASES.len()];
        visit(b ^ (step(&mut state) & 0x00ff_ffff));
    }
}
