//! Malformed input must produce errors, never panics.
//!
//! `Image::parse` and everything downstream read offsets, sizes and counts
//! straight out of the file. A truncated or corrupt binary is the normal case
//! for a tool like this — it gets pointed at whatever is on disk.

use sce_elf::{Image, ImplementedNids};

/// Runs the whole pipeline. Any `Err` is fine; a panic is not.
fn exercise(data: Vec<u8>) {
    let Ok(image) = Image::parse(data) else {
        return;
    };
    let _ = image.elf_type();
    for i in 0..image.program_headers.len() {
        let _ = image.segment_data(i);
    }
    let _ = image.data_at_vaddr(0, 16);
    let _ = image.imports();
    let _ = image.exports();
    let _ = image.compat_report(&ImplementedNids::new());
    if let Ok(dynamic) = image.dynamic() {
        let _ = dynamic.string(0);
        for sym in &dynamic.symbols {
            let _ = dynamic.decode_symbol(sym);
        }
        // Relocation application is the part that writes, so it matters most.
        if let Ok(mut loaded) = image.load(0x40_0000) {
            let _ = loaded.relocate(&dynamic, |_| Some(0x1000));
        }
    }
}

/// The two container headers, as a starting point to corrupt.
fn seeds() -> Vec<Vec<u8>> {
    let mut elf = Vec::new();
    elf.extend_from_slice(b"\x7FELF");
    elf.extend_from_slice(&[2, 1, 1, 0, 0]);
    elf.extend_from_slice(&[0u8; 7]);
    elf.extend_from_slice(&0xfe10u16.to_le_bytes());
    elf.extend_from_slice(&0x3eu16.to_le_bytes());
    elf.extend_from_slice(&1u32.to_le_bytes());
    elf.extend_from_slice(&0u64.to_le_bytes());
    elf.extend_from_slice(&64u64.to_le_bytes()); // e_phoff
    elf.extend_from_slice(&0u64.to_le_bytes());
    elf.extend_from_slice(&0u32.to_le_bytes());
    elf.extend_from_slice(&64u16.to_le_bytes());
    elf.extend_from_slice(&56u16.to_le_bytes());
    elf.extend_from_slice(&4u16.to_le_bytes()); // e_phnum
    elf.extend_from_slice(&[0u8; 6]);
    elf.resize(64 + 56 * 4 + 512, 0);

    let mut selff = Vec::new();
    selff.extend_from_slice(&0x1D3D_154Fu32.to_le_bytes());
    selff.extend_from_slice(&[0, 1, 1, 0x12, 1, 1]);
    selff.extend_from_slice(&0u16.to_le_bytes());
    selff.extend_from_slice(&0x400u16.to_le_bytes());
    selff.extend_from_slice(&0u16.to_le_bytes());
    selff.extend_from_slice(&0u32.to_le_bytes());
    selff.extend_from_slice(&0u32.to_le_bytes());
    selff.extend_from_slice(&2u16.to_le_bytes()); // segment_count
    selff.extend_from_slice(&0u16.to_le_bytes());
    selff.extend_from_slice(&0u32.to_le_bytes());
    selff.extend_from_slice(&[0u8; 64]); // two segment headers
    selff.extend_from_slice(&elf);

    vec![elf, selff]
}

#[test]
fn truncation_at_every_length_errors_cleanly() {
    for seed in seeds() {
        for len in 0..seed.len().min(400) {
            exercise(seed[..len].to_vec());
        }
    }
}

#[test]
fn corrupt_header_fields_error_cleanly() {
    // Values chosen to blow up naive arithmetic: maxima, and the boundaries
    // where `offset + size` wraps.
    let poisons: [u64; 7] = [
        u64::MAX,
        u64::MAX - 1,
        u64::MAX / 2,
        1 << 63,
        (1 << 32) - 1,
        1 << 32,
        0xffff_ffff_ffff_fff0,
    ];
    for seed in seeds() {
        // Smear each poison value over every 8-byte-aligned header slot.
        for offset in (0..seed.len().min(512)).step_by(8) {
            for poison in poisons {
                let mut data = seed.clone();
                if offset + 8 <= data.len() {
                    data[offset..offset + 8].copy_from_slice(&poison.to_le_bytes());
                    exercise(data);
                }
            }
        }
    }
}

#[test]
fn arbitrary_bytes_error_cleanly() {
    // A cheap deterministic PRNG: no dev-dependency, same corpus every run.
    let mut state = 0x243f_6a88_85a3_08d3u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for len in [0usize, 1, 4, 16, 32, 64, 128, 256, 1024] {
        for _ in 0..40 {
            let mut data: Vec<u8> = (0..len).map(|_| (next() >> 24) as u8).collect();
            exercise(data.clone());
            // And the same bytes behind each valid container magic, so the
            // parser gets past the first gate and into the real fields.
            for magic in [0x1D3D_154Fu32, 0xEEF5_1454] {
                if data.len() >= 4 {
                    data[..4].copy_from_slice(&magic.to_le_bytes());
                    exercise(data.clone());
                }
            }
        }
    }
}
