# 🤖 rust-SHELLCODE 🤖

This project provides the underlying support for bypass av of offensive activities.  
The available Shellcode loaders include:
* [asm](#asm)
* [create_fiber](#create_fiber)
* [create_remote_thread](#create_remote_thread)
* [create_remote_thread_native](#create_remote_thread_native)
* [create_thread](#create_thread)
* [create_thread_native](#create_thread_native)
* [early_bird](#early_bird)
* [etwp_create_etw_thread](#etwp_create_etw_thread)
* [memmap2_transmute](#memmap2_transmute)
* [nt_queue_apc_thread_ex_local](#nt_queue_apc_thread_ex_local)
* [rtl_create_user_thread](#rtl_create_user_thread)

## Build

This is a rust project, you need install [rust](https://www.rust-lang.org/) first.  
Then, you can build with follow command:

```shell
cargo build --release
```

Binarys in `target/release`

## How to use

This project is just a basic demo, you need to choose the right loading method, 
encrypt the SHELLCODE, download the SHELLCODE from the internet, 
or use it with ETW patch, unhooking, etc.

## asm

SHELLCODE execute locally.
1. link SHELLCODE to .text section
2. inline asm using asm! macro
3. call SHELLCODE

## create_fiber

SHELLCODE execute locally.
1. convert current thread to fiber using `ConvertThreadToFiber`
2. alloc memory using `VirtualAlloc`
3. copy SHELLCODE to allocated memory using `std::ptr::copy`
4. create a fiber using `CreateFiber`
5. jump SHELLCODE using `SwitchToFiber`
6. jump back

## create_remote_thread

SHELLCODE execute remotely.  
inject `explorer.exe` by default.
1. get pid by process name using crate `sysinfo`
2. get handle using `OpenProcess`
3. alloc remote memory using `VirtualAllocEx`
4. copy SHELLCODE to allocated memory using `WriteProcessMemory`
5. change memory permission to executable using `VirtualProtectEx`
6. execute SHELLCODE using `CreateRemoteThread`
7. close opened handle using `CloseHandle`

## create_remote_thread_native

SHELLCODE execute remotely.  
inject `explorer.exe` by default.  
this is same with [create_remote_thread](#create_remote_thread), but without crate `windows-sys`  
using crate `libloading` get functions from dlls.

## create_thread

SHELLCODE execute locally.
1. alloc remote memory using `VirtualAlloc`
2. copy SHELLCODE to allocated memory using `std::ptr::copy`
3. change memory permission to executable using `VirtualProtect`
4. execute SHELLCODE using `CreateThread`
5. waiting thread exit using `WaitForSingleObject`

## create_thread_native

SHELLCODE execute locally.  
this is same with [create_thread](#create_thread), but without crate `windows-sys`  
using crate `libloading` get functions from dlls.

## early_bird

SHELLCODE execute remotely.  
create and inject `svchost.exe` by default.
1. create a process using `CreateProcessA`
2. alloc remote memory using `VirtualAllocEx`
3. copy SHELLCODE to allocated memory using `WriteProcessMemory`
4. change memory permission to executable using `VirtualProtectEx`
5. execute process using `QueueUserAPC`
6. resume process's thread using `ResumeThread`
7. close opened handle using `CloseHandle`

## etwp_create_etw_thread

SHELLCODE execute locally.
1. get `EtwpCreateEtwThread` funtion from `ntdll` using `LoadLibraryA` and `GetProcAddress`
2. alloc remote memory using `VirtualAlloc`
3. copy SHELLCODE to allocated memory using `std::ptr::copy`
4. change memory permission to executable using `VirtualProtect`
5. execute SHELLCODE using `EtwpCreateEtwThread`
6. waiting thread exit using `WaitForSingleObject`

## memmap2_transmute

SHELLCODE execute locally.
1. alloc memory using crate `memmap2`
2. copy SHELLCODE using `copy_from_slice` function from `MmapMut` struct
3. change memory permission to executable using `make_exec` funtion from `MmapMut` struct
4. convert memory pointer to fn type using `transmute`
5. execute fn

## nt_queue_apc_thread_ex_local

SHELLCODE execute locally.
1. get `NtQueueApcThreadEx` funtion from `ntdll` using `LoadLibraryA` and `GetProcAddress`
2. alloc remote memory using `VirtualAlloc`
3. copy SHELLCODE to allocated memory using `std::ptr::copy`
4. change memory permission to executable using `VirtualProtect`
5. get current thread handle using `GetCurrentThread`
6. execute SHELLCODE using `NtQueueApcThreadEx`

## rtl_create_user_thread

SHELLCODE execute remotely.  
inject `explorer.exe` by default.
1. get `RtlCreateUserThread` funtion from `ntdll` using `LoadLibraryA` and `GetProcAddress`
2. get pid by process name using crate `sysinfo`
3. get handle using `OpenProcess`
4. alloc remote memory using `VirtualAllocEx`
5. copy SHELLCODE to allocated memory using `WriteProcessMemory`
6. change memory permission to executable using `VirtualProtectEx`
7. execute SHELLCODE using `RtlCreateUserThread`
8. close opened handle using `CloseHandle`
