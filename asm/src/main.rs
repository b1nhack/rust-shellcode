#![windows_subsystem = "windows"]

use std::arch::asm;

#[link_section = ".text"]
static SHELLCODE: [u8; 113] = *include_bytes!("../../win-exec-calc-shellcode.bin");

#[cfg(target_os = "windows")]
fn main() {
    unsafe {
        asm!(
        "call {}",
        in(reg) SHELLCODE.as_ptr(),
        )
    }
}
