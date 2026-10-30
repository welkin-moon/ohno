import http.client
import json
import re
import ssl
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.parse import urlencode
from http.server import ThreadingHTTPServer

from server import Handler, Store, create_certificate
from school_installer import get_school_configuration


class TeacherIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        root = Path(cls.temp.name)
        cls.store = Store.initialize(root/'state.json')
        subprocess.run([
            'openssl','req','-x509','-newkey','rsa:2048','-nodes',
            '-keyout',str(root/'key.pem'),'-out',str(root/'cert.pem'),
            '-days','1','-subj','/CN=localhost'
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)

        cls.api = ThreadingHTTPServer(('127.0.0.1',0), Handler)
        cls.api.store = cls.store
        cls.api.control = False
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(root/'cert.pem',root/'key.pem')
        cls.api.socket = context.wrap_socket(cls.api.socket,server_side=True)

        cls.control = ThreadingHTTPServer(('127.0.0.1',0), Handler)
        cls.control.store = cls.store
        cls.control.control = True
        cls.control.control_csrf = 'test-control-csrf'
        cls.control.school_installer_exe = root/'ohno-setup.exe'
        cls.control.school_installer_exe.write_bytes(b'MZ'+bytes(5000))
        cls.control.enrollment_origin = 'https://teacher-pc:8443'
        cls.control.public_certificate = (root/'cert.pem').read_bytes()

        cls.threads = [
            threading.Thread(target=cls.api.serve_forever,daemon=True),
            threading.Thread(target=cls.control.serve_forever,daemon=True),
        ]
        for thread in cls.threads: thread.start()

    @classmethod
    def tearDownClass(cls):
        for server in (cls.api,cls.control): server.shutdown(); server.server_close()
        for thread in cls.threads: thread.join()
        cls.temp.cleanup()

    def api_req(self,method,path,body=None,headers=None,raw=False):
        connection=http.client.HTTPSConnection('127.0.0.1',self.api.server_port,
            context=ssl._create_unverified_context(),timeout=5)
        headers=dict(headers or {});headers.setdefault('Host','teacher-pc')
        connection.request(method,path,body,headers)
        response=connection.getresponse();payload=response.read();result=(response.status,dict(response.getheaders()),payload if raw else payload.decode())
        connection.close();return result

    def control_req(self,method,path,body=None,headers=None,raw=False):
        connection=http.client.HTTPConnection('127.0.0.1',self.control.server_port,timeout=5)
        headers=dict(headers or {});headers.setdefault('Host','127.0.0.1')
        connection.request(method,path,body,headers)
        response=connection.getresponse();payload=response.read();result=(response.status,dict(response.getheaders()),payload if raw else payload.decode())
        connection.close();return result

    def csrf(self):
        status,_,page=self.control_req('GET','/')
        self.assertEqual(status,200)
        self.assertNotIn('管理密码',page)
        return re.search(r'name="csrf" value="([^"]+)',page).group(1)

    def form(self,path,values):
        status,_,text=self.control_req('POST',path,urlencode(values))
        self.assertEqual(status,303,text)

    def test_management_is_loopback_only_and_passwordless(self):
        self.assertEqual(self.api_req('GET','/')[0],404)
        self.assertEqual(self.api_req('GET','/school-installer')[0],404)
        self.assertEqual(self.control_req('POST','/api/device/register','{}')[0],404)
        status,_,page=self.control_req('GET','/')
        self.assertEqual(status,200)
        self.assertIn('仅本机可管理',page)
        self.assertNotIn('登录',page)
        self.assertNotIn('管理密码',page)
        self.assertEqual(self.control_req('POST','/policy',urlencode({'csrf':'wrong'}))[0],403)

    def test_complete_flow_and_optional_unlock_pin(self):
        csrf=self.csrf()
        status,_,_=self.control_req('POST','/policy',urlencode({'csrf':csrf,'domains':'games.example\nbad domain','hashes':''}))
        self.assertEqual(status,400)
        self.form('/policy',{'csrf':csrf,'domains':'games.example','hashes':'a'*64,'names':'gta3.exe','block_local_files':'1'})

        dev='A'*24;key='B'*32
        data=json.dumps({'id':dev,'key':key,'name':'<school-pc>','tun':True,'wfp':True,
                         'macs':['00:15:5d:11:22:33'],'primary_mac':'00:15:5d:11:22:33'})
        status,_,text=self.api_req('POST','/api/device/register',data)
        self.assertEqual(status,201);self.assertFalse(json.loads(text)['approved'])
        auth={'X-Ohno-Device':dev,'X-Ohno-Key':key}
        self.assertEqual(self.api_req('GET','/api/device/policy',headers=auth)[0],403)

        page=self.control_req('GET','/')[2]
        self.assertIn('&lt;school-pc&gt;',page)
        self.form('/device',{'csrf':csrf,'id':dev,'approved':'1'})
        status,_,body=self.api_req('GET','/api/device/policy',headers=auth)
        self.assertEqual(status,200);policy=json.loads(body)
        self.assertEqual(policy['web_domains'],['games.example'])
        self.assertEqual(policy['program_names'],['gta3.exe'])
        self.assertTrue(policy['block_local_files'])

        status,_,body=self.api_req('POST','/api/device/request',
            json.dumps({'kind':'website','object':'games.example','label':'<Game>.exe'}),auth)
        self.assertEqual(status,201);request_id=json.loads(body)['id']
        self.assertIn('&lt;Game&gt;.exe',self.control_req('GET','/')[2])
        self.form('/request',{'csrf':csrf,'id':request_id,'action':'approve'})

        # No PIN exists by default; local teacher management itself still needs no password.
        self.assertEqual(self.api_req('POST','/api/device/unlock',json.dumps({'pin':'2468'}),auth)[0],403)
        self.form('/unlock-pin',{'csrf':csrf,'action':'set','pin':'2468'})
        self.assertEqual(self.api_req('POST','/api/device/unlock',json.dumps({'pin':'0000'}),auth)[0],403)
        self.assertEqual(self.api_req('POST','/api/device/unlock',json.dumps({'pin':'2468'}),auth)[0],201)
        self.assertTrue(any(x['kind']=='pause' for x in json.loads(self.api_req('GET','/api/device/policy',headers=auth)[2])['grants']))
        self.form('/unlock-pin',{'csrf':csrf,'action':'clear','pin':''})
        self.assertEqual(self.api_req('POST','/api/device/unlock',json.dumps({'pin':'2468'}),auth)[0],403)

        saved=json.loads(Path(self.store.path).read_text())
        self.assertNotIn(key,json.dumps(saved))
        self.assertNotIn('2468',json.dumps(saved))
        self.assertNotIn('password_hash',saved)

    def test_mac_binding_rebind_conflicts_and_dhcp(self):
        dev,key='C'*24,'D'*32
        first,second='00:15:5d:11:22:44','00:15:5d:11:22:45'
        def reg(device=dev,secret=key,mac=first,source_ip='192.168.1.20'):
            return self.api_req('POST','/api/device/register',json.dumps(
                {'id':device,'key':secret,'name':'lab-pc','macs':[mac],'primary_mac':mac,'ip':source_ip}))
        status,_,data=reg();self.assertEqual(status,201);self.assertFalse(json.loads(data)['approved'])
        self.assertEqual(self.api_req('POST','/api/device/register',json.dumps(
            {'id':dev,'key':key,'name':'lab-pc','macs':[first,first],'primary_mac':first}))[0],400)
        auth={'X-Ohno-Device':dev,'X-Ohno-Key':key}
        csrf=self.csrf()
        def approve(device,value='1'): return self.control_req('POST','/device',urlencode({'csrf':csrf,'id':device,'approved':value}))[0]
        self.assertEqual(approve(dev),303)
        self.assertEqual(self.api_req('GET','/api/device/policy',headers=auth)[0],200)
        status,_,data=reg(source_ip='192.168.1.83');self.assertEqual(status,200);self.assertTrue(json.loads(data)['approved'])
        self.assertEqual(self.store.data['devices'][dev]['bound_mac'],first)
        self.assertEqual(self.store.data['devices'][dev]['last_ip'],'127.0.0.1')
        self.assertEqual(reg(secret='wrong-secret-not-accepted')[0],403)
        status,_,data=reg(mac=second);self.assertEqual(status,200);self.assertFalse(json.loads(data)['approved'])
        self.assertEqual(self.api_req('GET','/api/device/policy',headers=auth)[0],403)
        self.assertIn('MAC 变更',self.control_req('GET','/')[2])
        self.assertEqual(approve(dev),303)
        second_dev,second_key='E'*24,'F'*32
        self.assertEqual(reg(device=second_dev,secret=second_key,mac=second)[0],201)
        self.assertEqual(approve(second_dev),409)
        self.assertEqual(approve(dev,'0'),303)
        self.assertEqual(approve(second_dev),303)

    def test_school_installer_download_from_local_control_only(self):
        self.assertEqual(self.api_req('GET','/school-installer')[0],404)
        status,headers,payload=self.control_req('GET','/school-installer',raw=True)
        self.assertEqual(status,200)
        self.assertIn('Ohno-School-Setup.exe',headers['Content-Disposition'])
        url,cert=get_school_configuration(payload)
        self.assertEqual(url,'https://teacher-pc:8443')
        self.assertEqual(cert,self.control.public_certificate)
        self.assertEqual(payload[:2],b'MZ')

    def test_certificate_generation(self):
        with tempfile.TemporaryDirectory() as temp:
            cert=Path(temp)/'cert.pem';key=Path(temp)/'key.pem'
            create_certificate(cert,key,'localhost')
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key)
            with self.assertRaises(FileExistsError):create_certificate(cert,key,'localhost')

    def test_state_no_overwrite(self):
        with self.assertRaises(FileExistsError):Store.initialize(self.store.path)


if __name__ == '__main__': unittest.main()
