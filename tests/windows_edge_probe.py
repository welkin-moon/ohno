"""Exercise Edge policy against a local HTTP page on an ephemeral Windows runner."""
import os
import subprocess
import tempfile
import threading
import winreg
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

MARKER='ohno-browser-policy-fixture-7e03'
class Page(BaseHTTPRequestHandler):
    def do_GET(self):
        data=('<!doctype html><title>'+MARKER+'</title><p>'+MARKER+'</p>').encode()
        self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
    def log_message(self,*args):pass


def main():
    edge=next((p for p in [Path(os.environ.get('PROGRAMFILES(X86)',''))/'Microsoft/Edge/Application/msedge.exe',Path(os.environ.get('PROGRAMFILES',''))/'Microsoft/Edge/Application/msedge.exe'] if p.exists()),None)
    if not edge:raise RuntimeError('Microsoft Edge is not installed on the runner')
    path=r'SOFTWARE\Policies\Microsoft\Edge\URLBlocklist'
    server=HTTPServer(('127.0.0.1',0),Page);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    with tempfile.TemporaryDirectory() as tmp:
        browser_key=winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE,path,0,winreg.KEY_READ|winreg.KEY_WRITE|winreg.KEY_WOW64_64KEY)
        try:
            try:previous=winreg.QueryValueEx(browser_key,'1')
            except FileNotFoundError:previous=None
            def run(address,idx):
                args=[str(edge),'--headless','--disable-gpu','--no-first-run','--disable-background-networking','--user-data-dir='+str(Path(tmp)/('profile'+str(idx))),'--dump-dom',address]
                result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=45)
                return result.stdout.decode('utf-8','replace')
            url='http://localhost:%d/'%server.server_port
            winreg.DeleteValue(browser_key,'1') if previous else None
            if MARKER not in run(url,0):raise RuntimeError('Baseline local page did not load in Edge')
            winreg.SetValueEx(browser_key,'1',0,winreg.REG_SZ,'localhost')
            blocked=run(url,1)
            if MARKER in blocked:raise RuntimeError('Edge URLBlocklist did not block localhost')
            if '<html' not in blocked.lower():raise RuntimeError('Blocked page could not be distinguished from browser failure')
            print('Edge domain policy blocked the local page')
            local=Path(tmp)/'local.html';local.write_text('<title>'+MARKER+'</title>',encoding='utf-8')
            local_url=local.as_uri()
            if MARKER not in run(local_url,9):raise RuntimeError('Baseline local file did not load in Edge')
            for i,pattern in enumerate(['file://*','file:///*','file:*'],2):
                winreg.SetValueEx(browser_key,'1',0,winreg.REG_SZ,pattern)
                output=run(local_url,i)
                print('local pattern %s: %s'%(pattern,'BLOCKED' if MARKER not in output else 'NOT BLOCKED'))
        finally:
            if previous:winreg.SetValueEx(browser_key,'1',0,previous[1],previous[0])
            else:
                try:winreg.DeleteValue(browser_key,'1')
                except FileNotFoundError:pass
            winreg.CloseKey(browser_key)
            server.shutdown();server.server_close();thread.join()

if __name__=='__main__':main()
