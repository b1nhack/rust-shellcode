# :japanese_ogre:rust-shellcode

* [asm](#asm)
* [create_fiber](#create_fiber)
* [create_remote_thread](#create_remote_thread)
* [create_remote_thread_native](#create_remote_thread_native)
* [create_thread](#create_thread)
* [create_thread_native](#create_thread_native)
* [etwp_create_etw_thread](#etwp_create_etw_thread)
* [nt_queue_apc_thread_ex_local](#nt_queue_apc_thread_ex_local)
* [rtl_create_user_thread](#rtl_create_user_thread)

## asm

shellcode execute locally.
1. link shellcode to .text section
2. inline asm using asm! macro
3. call shellcode

## create_fiber

shellcode execute locally.
1. convert current thread to fiber using `ConvertThreadToFiber`
2. alloc memory using `VirtualAlloc`
3. copy shellcode to allocated memory using `std::ptr::copy`
4. create a fiber using `CreateFiber`
5. jump shellcode using `SwitchToFiber`
6. jump back

## create_remote_thread

shellcode execute remotely.  
inject `explorer.exe` by default.
1. get pid by process name using crate `sysinfo`
2. get handle using `OpenProcess`
3. alloc remote memory using `VirtualAllocEx`
4. copy shellcode to allocated memory using `WriteProcessMemory`
5. change memory permission to executable using `VirtualProtectEx`
6. execute shellcode using `CreateRemoteThread`
7. close opened handle using `CloseHandle`

## create_remote_thread_native

shellcode execute remotely.  
inject `explorer.exe` by default.  
this is same with [create_remote_thread](#create_remote_thread), but without crate `windows-sys`  
using crate `libloading` get functions from dlls.

## create_thread

shellcode execute locally.
1. alloc remote memory using `VirtualAlloc`
2. copy shellcode to allocated memory using `std::ptr::copy`
3. change memory permission to executable using `VirtualProtect`
4. execute shellcode using `CreateThread`
5. waiting thread exit using `WaitForSingleObject`

## create_thread_native

shellcode execute locally.  
this is same with [create_thread](#create_thread), but without crate `windows-sys`  
using crate `libloading` get functions from dlls.

## etwp_create_etw_thread

shellcode execute locally.
1. get `EtwpCreateEtwThread` funtion from `ntdll` using `LoadLibraryA` and `GetProcAddress`
2. alloc remote memory using `VirtualAlloc`
3. copy shellcode to allocated memory using `std::ptr::copy`
4. change memory permission to executable using `VirtualProtect`
5. execute shellcode using `EtwpCreateEtwThread`
6. waiting thread exit using `WaitForSingleObject`

## nt_queue_apc_thread_ex_local

shellcode execute locally.
1. get `NtQueueApcThreadEx` funtion from `ntdll` using `LoadLibraryA` and `GetProcAddress`
2. alloc remote memory using `VirtualAlloc`
3. copy shellcode to allocated memory using `std::ptr::copy`
4. change memory permission to executable using `VirtualProtect`
5. get current thread handle using `GetCurrentThread`
6. execute shellcode using `NtQueueApcThreadEx`

## rtl_create_user_thread

shellcode execute remotely.  
inject `explorer.exe` by default.
1. get `RtlCreateUserThread` funtion from `ntdll` using `LoadLibraryA` and `GetProcAddress`
2. get pid by process name using crate `sysinfo`
3. get handle using `OpenProcess`
4. alloc remote memory using `VirtualAllocEx`
5. copy shellcode to allocated memory using `WriteProcessMemory`
6. change memory permission to executable using `VirtualProtectEx`
7. execute shellcode using `RtlCreateUserThread`
8. close opened handle using `CloseHandle`
