import http.client
import json
import os
import re
import ssl
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.parse import urlencode
from server import Handler, Store, create_certificate
from http.server import ThreadingHTTPServer


class TeacherIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        root = Path(cls.temp.name)
        cls.store = Store.initialize(root/'state.json', 'a-strong-test-password')
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(root/'key.pem'),'-out',str(root/'cert.pem'),'-days','1','-subj','/CN=localhost'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        cls.server = ThreadingHTTPServer(('127.0.0.1',0), Handler)
        cls.server.store = cls.store
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(root/'cert.pem',root/'key.pem')
        cls.server.socket = context.wrap_socket(cls.server.socket,server_side=True)
        cls.thread = threading.Thread(target=cls.server.serve_forever,daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join(); cls.temp.cleanup()

    def req(self,method,path,body=None,headers=None):
        c = http.client.HTTPSConnection('127.0.0.1',self.server.server_port,context=ssl._create_unverified_context(),timeout=5)
        c.request(method,path,body,headers or {})
        r=c.getresponse(); result=(r.status,dict(r.getheaders()),r.read().decode());c.close();return result

    def test_complete_flow(self):
        status, _, _ = self.req('POST','/login',urlencode({'password':'wrong'})); self.assertEqual(status,403)
        status, headers, _ = self.req('POST','/login',urlencode({'password':'a-strong-test-password'})); self.assertEqual(status,303)
        cookie=headers['Set-Cookie'].split(';')[0]
        status, _, page=self.req('GET','/',headers={'Cookie':cookie});self.assertEqual(status,200)
        csrf=re.search(r'name="csrf" value="([^"]+)',page).group(1)
        status, _, _ = self.req('POST','/policy',urlencode({'csrf':'wrong','domains':'games.example'}),{'Cookie':cookie});self.assertEqual(status,403)
        status, _, _ = self.req('POST','/policy',urlencode({'csrf':csrf,'domains':'games.example\nbad domain','hashes':''}),{'Cookie':cookie});self.assertEqual(status,400)
        status, _, _ = self.req('POST','/policy',urlencode({'csrf':csrf,'domains':'games.example','hashes':'a'*64,'names':'gta3.exe','block_local_files':'1'}),{'Cookie':cookie});self.assertEqual(status,303)
        dev='A'*24;key='B'*32
        data=json.dumps({'id':dev,'key':key,'name':'<school-pc>'})
        status, _, text=self.req('POST','/api/device/register',data);self.assertEqual(status,201);self.assertFalse(json.loads(text)['approved'])
        auth={'X-Ohno-Device':dev,'X-Ohno-Key':key}
        self.assertEqual(self.req('GET','/api/device/policy',headers=auth)[0],403)
        status, _, page=self.req('GET','/',headers={'Cookie':cookie});self.assertIn('&lt;school-pc&gt;',page)
        status, _, _=self.req('POST','/device',urlencode({'csrf':csrf,'id':dev,'approved':'1'}),{'Cookie':cookie});self.assertEqual(status,303)
        status, _, body=self.req('GET','/api/device/policy',headers=auth);self.assertEqual(status,200);self.assertEqual(json.loads(body)['web_domains'],['games.example']);self.assertEqual(json.loads(body)['program_names'],['gta3.exe']);self.assertTrue(json.loads(body)['block_local_files'])
        status, _, body=self.req('POST','/api/device/request',json.dumps({'kind':'website','object':'games.example','label':'<Game>.exe'}),auth);self.assertEqual(status,201);request_id=json.loads(body)['id']
        self.assertIn('&lt;Game&gt;.exe',self.req('GET','/',headers={'Cookie':cookie})[2])
        status, _, _=self.req('POST','/request',urlencode({'csrf':csrf,'id':request_id,'action':'approve'}),{'Cookie':cookie});self.assertEqual(status,303)
        status, _, body=self.req('GET','/api/device/policy',headers=auth);self.assertEqual(status,200);self.assertEqual(json.loads(body)['grants'][0]['object'],'games.example')
        self.assertEqual(self.req('POST','/api/device/unlock',json.dumps({'password':'wrong'}),auth)[0],403)
        self.assertEqual(self.req('POST','/api/device/unlock',json.dumps({'password':'a-strong-test-password'}),auth)[0],201)
        self.assertTrue(any(x['kind']=='pause' for x in json.loads(self.req('GET','/api/device/policy',headers=auth)[2])['grants']))
        self.assertEqual(self.req('GET','/api/device/policy',headers={'X-Ohno-Device':dev,'X-Ohno-Key':'wrong'})[0],403)
        status, _, _=self.req('POST','/device',urlencode({'csrf':csrf,'id':dev,'approved':'0'}),{'Cookie':cookie});self.assertEqual(status,303)
        self.assertEqual(self.req('GET','/api/device/policy',headers=auth)[0],403)
        saved=json.loads(Path(self.store.path).read_text()); self.assertNotIn(key, json.dumps(saved)); self.assertNotIn('a-strong-test-password',json.dumps(saved))

    def test_certificate_generation(self):
        with tempfile.TemporaryDirectory() as temp:
            cert=Path(temp)/'cert.pem';key=Path(temp)/'key.pem'
            create_certificate(cert,key,'localhost')
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key)
            with self.assertRaises(FileExistsError):create_certificate(cert,key,'localhost')

    def test_state_no_overwrite(self):
        with self.assertRaises(FileExistsError): Store.initialize(self.store.path,'another-strong-password')

if __name__ == '__main__': unittest.main()
