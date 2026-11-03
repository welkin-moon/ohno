"""Own disposable GUI processes only; no service/account/production credentials.

The fixture links the real window/controller to a separate deterministic sender.
The production binary is also checked against an absent service. Authenticated
real-SYSTEM transport stays covered by the full installed-service E2E suite.
"""
import ctypes as c
from contextlib import contextmanager
from pathlib import Path
import struct
import subprocess
import time

ui=c.WinDLL('user32',use_last_error=True)
kernel=c.WinDLL('kernel32',use_last_error=True)
HWND=c.c_void_p
ui.EnumWindows.argtypes=[c.WINFUNCTYPE(c.c_int,HWND,c.c_ssize_t),c.c_ssize_t]
ui.GetWindowThreadProcessId.argtypes=[HWND,c.POINTER(c.c_uint32)]
ui.GetClassNameW.argtypes=[HWND,c.c_wchar_p,c.c_int]
ui.GetDlgItem.argtypes=[HWND,c.c_int];ui.GetDlgItem.restype=HWND
ui.SendMessageTimeoutW.argtypes=[HWND,c.c_uint,c.c_size_t,c.c_ssize_t,c.c_uint,c.c_uint,c.POINTER(c.c_size_t)]
ui.SendMessageTimeoutW.restype=c.c_size_t
ui.PostMessageW.argtypes=[HWND,c.c_uint,c.c_size_t,c.c_ssize_t]
ui.IsWindowEnabled.argtypes=[HWND]
kernel.CreateSemaphoreW.argtypes=[c.c_void_p,c.c_long,c.c_long,c.c_wchar_p];kernel.CreateSemaphoreW.restype=HWND
kernel.CreateEventW.argtypes=[c.c_void_p,c.c_int,c.c_int,c.c_wchar_p];kernel.CreateEventW.restype=HWND
kernel.SetEvent.argtypes=[HWND];kernel.ResetEvent.argtypes=[HWND]
kernel.WaitForSingleObject.argtypes=[HWND,c.c_uint32]
kernel.CloseHandle.argtypes=[HWND]


def capture(window,name):
    # Only fixture website/status screens; no entered PIN/credentials captured.
    class Rect(c.Structure):
        _fields_=[('left',c.c_long),('top',c.c_long),('right',c.c_long),('bottom',c.c_long)]
    gdi=c.WinDLL('gdi32',use_last_error=True)
    ui.GetWindowRect.argtypes=[HWND,c.POINTER(Rect)]
    ui.GetWindowDC.argtypes=[HWND];ui.GetWindowDC.restype=HWND
    ui.ReleaseDC.argtypes=[HWND,HWND]
    ui.PrintWindow.argtypes=[HWND,HWND,c.c_uint]
    gdi.CreateCompatibleDC.argtypes=[HWND];gdi.CreateCompatibleDC.restype=HWND
    gdi.CreateCompatibleBitmap.argtypes=[HWND,c.c_int,c.c_int];gdi.CreateCompatibleBitmap.restype=HWND
    gdi.SelectObject.argtypes=[HWND,HWND];gdi.SelectObject.restype=HWND
    gdi.GetDIBits.argtypes=[HWND,HWND,c.c_uint,c.c_uint,c.c_void_p,c.c_void_p,c.c_uint]
    gdi.DeleteObject.argtypes=[HWND];gdi.DeleteDC.argtypes=[HWND]
    rect=Rect();assert ui.GetWindowRect(window,c.byref(rect))
    width,height=rect.right-rect.left,rect.bottom-rect.top
    assert width>0 and height>0
    dc=ui.GetWindowDC(window);memory=gdi.CreateCompatibleDC(dc)
    bitmap=gdi.CreateCompatibleBitmap(dc,width,height);old=gdi.SelectObject(memory,bitmap)
    try:
        assert dc and memory and bitmap and old and ui.PrintWindow(window,memory,0)
        gdi.SelectObject(memory,old);old=None
        pixels=c.create_string_buffer(width*height*4)
        header=struct.pack('<IiiHHIIiiII',40,width,-height,1,32,0,len(pixels),0,0,0,0)
        info=c.create_string_buffer(header)
        assert gdi.GetDIBits(dc,bitmap,0,height,pixels,info,0)==height
        directory=Path('request-ui-evidence');directory.mkdir(exist_ok=True)
        (directory/(name+'.bmp')).write_bytes(struct.pack('<2sIHHI',b'BM',54+len(pixels),0,0,54)+header+pixels.raw)
    finally:
        if old:gdi.SelectObject(memory,old)
        if bitmap:gdi.DeleteObject(bitmap)
        if memory:gdi.DeleteDC(memory)
        if dc:ui.ReleaseDC(window,dc)


def waitfor(check,seconds=5):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        result=check()
        if result:return result
        time.sleep(.02)
    raise AssertionError('GUI condition timed out')


def window_for(pid):
    found=[]
    @c.WINFUNCTYPE(c.c_int,HWND,c.c_ssize_t)
    def visit(window,_):
        owner=c.c_uint32();ui.GetWindowThreadProcessId(window,c.byref(owner))
        name=c.create_unicode_buffer(128);ui.GetClassNameW(window,name,128)
        if owner.value==pid and name.value=='OhnoRequestWindow':found.append(window)
        return 1
    assert ui.EnumWindows(visit,0)
    return found[0] if found else None


def send(window,message,wp=0,lp=0):
    result=c.c_size_t()
    assert ui.SendMessageTimeoutW(window,message,wp,lp,2,1000,c.byref(result)), 'UI thread stopped responding'
    return result.value


def control(window,id):
    result=ui.GetDlgItem(window,id);assert result
    return result


def set_text(window,id,text):
    buffer=c.create_unicode_buffer(text)
    assert send(control(window,id),0x000c,0,c.addressof(buffer))


def text(window,id):
    buffer=c.create_unicode_buffer(512)
    send(control(window,id),0x000d,len(buffer),c.addressof(buffer))
    return buffer.value


def command(window,id):send(window,0x0111,id)
def enabled(window,id):return bool(ui.IsWindowEnabled(control(window,id)))


@contextmanager
def launch(binary,fixture=False):
    process=subprocess.Popen([str(Path(binary).resolve())]);handles=[]
    try:
        if fixture:
            prefix='Local\\OhnoRequestGuiTest-'+str(process.pid)
            handles=[kernel.CreateSemaphoreW(None,0,100,prefix+'-calls'),
                     kernel.CreateEventW(None,True,False,prefix+'-finish'),
                     kernel.CreateEventW(None,True,False,prefix+'-timeout')]
            assert all(handles)
        window=waitfor(lambda:window_for(process.pid))
        yield process,window,handles
    finally:
        if process.poll() is None:
            window=window_for(process.pid)
            if window:ui.PostMessageW(window,0x0010,0,0)
            try:process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill();process.wait(timeout=3)
                raise AssertionError('owned GUI did not close normally')
        for handle in handles:
            if handle:kernel.CloseHandle(handle)


def pending(window,calls,id=102):
    if id==102:set_text(window,101,'test.example')
    else:set_text(window,103,'2468')
    command(window,id)
    assert kernel.WaitForSingleObject(calls,3000)==0
    assert not any(enabled(window,id) for id in (101,102,103,104))
    assert enabled(window,2)
    assert text(window,103)==''
    for _ in range(5):command(window,102);command(window,104)
    assert kernel.WaitForSingleObject(calls,50)==258, 'duplicate request started'
    send(window,0) # responsive WM_NULL while its worker is waiting


def main():
    with launch('request-ui-fixture.exe',True) as (process,window,handles):
        calls,finish,timeout=handles
        capture(window,'idle')
        set_text(window,103,'not-a-PIN');command(window,104)
        assert text(window,103)=='' and '数字' in text(window,105)
        assert kernel.WaitForSingleObject(calls,0)==258
        pending(window,calls)
        capture(window,'pending')
        command(window,2)
        waitfor(lambda:enabled(window,102))
        waitfor(lambda:'已取消等待' in text(window,105))
        capture(window,'cancelled')
        assert kernel.WaitForSingleObject(calls,0)==258, 'cancel replayed request'
        pending(window,calls,104);assert kernel.SetEvent(finish)
        waitfor(lambda:enabled(window,102))
        waitfor(lambda:'PIN 验证通过' in text(window,105))
        assert kernel.ResetEvent(finish)
        pending(window,calls);assert kernel.SetEvent(timeout)
        waitfor(lambda:enabled(window,102))
        waitfor(lambda:'等待超时' in text(window,105))
        assert kernel.ResetEvent(timeout)
        assert kernel.WaitForSingleObject(calls,0)==258, 'timeout replayed request'
        pending(window,calls,104)
        start=time.monotonic();assert ui.PostMessageW(window,0x0010,0,0)
        assert process.wait(timeout=3)==0 and time.monotonic()-start<3
    # Reopen after an interrupted request: no stale completion, PIN or request.
    with launch('request-ui-fixture.exe',True) as (_,window,handles):
        assert text(window,103)=='' and text(window,105)=='' and enabled(window,102)
        assert kernel.WaitForSingleObject(handles[0],100)==258
    with launch('ohno-request.exe') as (_,window,_):
        set_text(window,103,'2468');command(window,104)
        waitfor(lambda:enabled(window,102))
        waitfor(lambda:'尚未发送' in text(window,105))
        assert text(window,103)==''
    print('Real GUI: invalid PIN, single-flight repeats, Cancel, timeout, Close, reopen and absent-service paths passed')


if __name__=='__main__':main()
