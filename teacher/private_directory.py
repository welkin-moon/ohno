"""Create a NEW private directory without changing any existing permissions."""
import os
from pathlib import Path


def create_private_directory(path: Path):
    path=Path(path)
    if os.name!='nt':
        path.mkdir(mode=0o700)
        return
    import ctypes
    from ctypes import wintypes as w
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    security=ctypes.WinDLL('advapi32',use_last_error=True)
    kernel.GetCurrentProcess.restype=w.HANDLE
    kernel.CloseHandle.argtypes=[w.HANDLE]
    kernel.LocalFree.argtypes=[ctypes.c_void_p];kernel.LocalFree.restype=ctypes.c_void_p
    security.OpenProcessToken.argtypes=[w.HANDLE,w.DWORD,ctypes.POINTER(w.HANDLE)]
    security.GetTokenInformation.argtypes=[w.HANDLE,ctypes.c_int,ctypes.c_void_p,w.DWORD,ctypes.POINTER(w.DWORD)]
    security.ConvertSidToStringSidW.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_void_p)]
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes=[w.LPCWSTR,w.DWORD,ctypes.POINTER(ctypes.c_void_p),ctypes.POINTER(w.DWORD)]
    class Attributes(ctypes.Structure):
        _fields_=[('length',w.DWORD),('descriptor',ctypes.c_void_p),('inherit',w.BOOL)]
    class TokenUser(ctypes.Structure):
        _fields_=[('sid',ctypes.c_void_p),('attributes',w.DWORD)]
    kernel.CreateDirectoryW.argtypes=[w.LPCWSTR,ctypes.POINTER(Attributes)]
    kernel.GetVolumePathNameW.argtypes=[w.LPCWSTR,w.LPWSTR,w.DWORD]
    kernel.GetVolumeInformationW.argtypes=[w.LPCWSTR,w.LPWSTR,w.DWORD,ctypes.c_void_p,ctypes.c_void_p,ctypes.POINTER(w.DWORD),w.LPWSTR,w.DWORD]
    token=w.HANDLE();sid_string=ctypes.c_void_p();descriptor=ctypes.c_void_p()
    def require(ok):
        if not ok:raise ctypes.WinError(ctypes.get_last_error())
    try:
        volume=ctypes.create_unicode_buffer(32768);flags=w.DWORD()
        require(kernel.GetVolumePathNameW(str(path.parent),volume,32768))
        require(kernel.GetVolumeInformationW(volume,None,0,None,None,ctypes.byref(flags),None,0))
        if not flags.value & 8:raise OSError('release keys require persistent filesystem ACLs')
        require(security.OpenProcessToken(kernel.GetCurrentProcess(),8,ctypes.byref(token))) # TOKEN_QUERY
        size=w.DWORD();security.GetTokenInformation(token,1,None,0,ctypes.byref(size))
        require(0<size.value<=65536)
        buffer=ctypes.create_string_buffer(size.value)
        require(security.GetTokenInformation(token,1,buffer,size.value,ctypes.byref(size)))
        user=ctypes.cast(buffer,ctypes.POINTER(TokenUser)).contents
        require(security.ConvertSidToStringSidW(user.sid,ctypes.byref(sid_string)))
        sid=ctypes.wstring_at(sid_string)
        # Protected DACL, inheritable only by SYSTEM, built-in Administrators,
        # and this process's user. Created atomically BEFORE writing private keys.
        sddl='D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;'+sid+')'
        require(security.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,1,ctypes.byref(descriptor),None))
        attributes=Attributes(ctypes.sizeof(Attributes),descriptor,False)
        if not kernel.CreateDirectoryW(str(path),ctypes.byref(attributes)):
            error=ctypes.get_last_error()
            if error==183:raise FileExistsError(str(path))
            raise ctypes.WinError(error)
    finally:
        if descriptor:kernel.LocalFree(descriptor)
        if sid_string:kernel.LocalFree(sid_string)
        if token:kernel.CloseHandle(token)
