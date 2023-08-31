use std::arch::asm;

#[cfg(target_os = "windows")]
fn main() {
    #[link_section = ".text"]
    static SHELLCODE: [u8; 98] = *include_bytes!("../../w64-exec-calc-shellcode-func.bin");

    unsafe {
        asm!(
        "call {}",
        in(reg) SHELLCODE.as_ptr(),
        )
    }
}
