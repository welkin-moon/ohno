import http.client
import json
import re
import socket
import ssl
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.parse import urlencode
from unittest.mock import patch

from server import Handler, Store, TeacherHTTPServer, create_certificate, serve_teacher
from school_installer import get_school_configuration


class TeacherIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        root = Path(cls.temp.name)
        cls.store = Store.initialize(root/'state.json')
        create_certificate(root/'cert.pem', root/'key.pem', 'localhost')

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(root/'cert.pem',root/'key.pem')
        cls.api = TeacherHTTPServer(('127.0.0.1',0), Handler, ssl_context=context)
        cls.api.store = cls.store
        cls.api.control = False
        cls.client_context = ssl.create_default_context(cafile=str(root/'cert.pem'))

        cls.control = TeacherHTTPServer(('127.0.0.1',0), Handler)
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

    def setUp(self):
        # Each test gets independent state while reusing the listening sockets.
        root = Path(self.temp.name) / self._testMethodName
        self.store = Store.initialize(root/'state.json')
        self.api.store = self.control.store = self.store

    @classmethod
    def tearDownClass(cls):
        for server in (cls.api,cls.control): server.shutdown(); server.server_close()
        for thread in cls.threads: thread.join()
        cls.temp.cleanup()

    def api_req(self,method,path,body=None,headers=None,raw=False):
        connection=http.client.HTTPSConnection('127.0.0.1',self.api.server_port,
            context=self.client_context,timeout=5)
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
        self.assertNotIn('action="/login"',page)
        self.assertNotIn('name="password"',page)
        return re.search(r'name="csrf" value="([^"]+)',page).group(1)

    def form(self,path,values):
        status,_,text=self.control_req('POST',path,urlencode(values))
        self.assertEqual(status,303,text)

    def approved_device(self):
        dev, key = 'R'*24, 'S'*32
        payload = {'id': dev, 'key': key, 'name': 'test-pc',
                   'macs': ['00:15:5d:77:88:99'], 'primary_mac': '00:15:5d:77:88:99'}
        self.assertEqual(self.api_req('POST', '/api/device/register', json.dumps(payload))[0], 201)
        self.form('/device', {'csrf': self.csrf(), 'id': dev, 'approved': '1'})
        return {'X-Ohno-Device': dev, 'X-Ohno-Key': key}

    def maintenance_request(self, password='A classroom maintenance phrase!', action='install', auth=None, nonce='c'*64):
        return self.api_req('POST', '/api/maintenance/authorize', json.dumps({
            'action': action, 'nonce': nonce, 'maintenance_password': password}), auth)

    def test_maintenance_control_and_authorization_are_separate(self):
        self.assertEqual(self.maintenance_request()[0], 403)
        self.assertEqual(self.control_req('POST', '/api/maintenance/authorize', '{}')[0], 404)
        values = {'csrf': self.csrf(), 'action': 'set', 'maintenance_password': 'A classroom maintenance phrase!'}
        self.assertEqual(self.api_req('POST', '/maintenance-password', urlencode(values))[0], 404)
        self.assertEqual(self.control_req('POST', '/maintenance-password', urlencode(dict(values, csrf='wrong')))[0], 403)
        self.assertIsNone(self.store.data.get('maintenance_credential'))
        self.form('/maintenance-password', values)
        status, _, body = self.maintenance_request()
        self.assertEqual(status, 200)
        decision = json.loads(body)
        self.assertEqual(decision['action'], 'install')
        self.assertEqual(decision['nonce'], 'c'*64)
        self.assertEqual(decision['device_id'], '')
        self.assertEqual(decision['expires_at'] - decision['authorized_at'], 120)
        self.assertTrue(decision['authorized'])
        self.assertNotIn('token', decision)
        saved = self.store.path.read_text('utf-8')
        self.assertNotIn(values['maintenance_password'], saved)
        self.assertEqual(len(self.store.data['maintenance_events']), 1)
        self.assertEqual(Store(self.store.path).data['maintenance_credential'], self.store.data['maintenance_credential'])
        # No maintenance login is added to everyday control or device registration.
        self.form('/policy', {'csrf': self.csrf(), 'domains': '', 'names': '', 'hashes': ''})
        self.assertEqual(self.api_req('POST', '/api/device/register', json.dumps({
            'id': 'Q'*24, 'key': 'W'*32, 'name': 'fresh-clone'}))[0], 201)
        _, _, installer = self.control_req('GET', '/school-installer', raw=True)
        self.assertNotIn(values['maintenance_password'].encode(), installer)
        self.assertNotIn(self.store.data['maintenance_credential']['digest'].encode(), installer)
        self.form('/maintenance-password', {'csrf': self.csrf(), 'action': 'clear'})
        self.assertEqual(self.maintenance_request()[0], 403)

    def test_uninstall_requires_device_key_but_not_current_approval(self):
        self.store.set_maintenance_password('A classroom maintenance phrase!')
        self.assertEqual(self.api_req('POST', '/api/device/register', json.dumps({
            'id': 'Q'*24, 'key': 'W'*32, 'name': 'pending-device'}))[0], 201)
        auth = {'X-Ohno-Device': 'Q'*24, 'X-Ohno-Key': 'W'*32}
        self.assertEqual(self.maintenance_request(action='uninstall')[0], 403)
        self.assertEqual(self.maintenance_request(action='uninstall', auth=dict(auth, **{'X-Ohno-Key': 'wrong'}))[0], 403)
        status, _, body = self.maintenance_request(action='uninstall', auth=auth)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)['device_id'], 'Q'*24)
        self.assertFalse(self.store.data['devices']['Q'*24]['approved'])

    def test_maintenance_password_is_not_classroom_pin(self):
        self.store.set_maintenance_password('A classroom maintenance phrase!')
        self.store.set_unlock_pin('2468')
        auth = self.approved_device()
        self.assertEqual(self.maintenance_request(password='2468')[0], 403)
        self.assertEqual(self.api_req('POST', '/api/device/unlock',
            json.dumps({'pin': 'A classroom maintenance phrase!'}), auth)[0], 400)
        self.assertEqual(self.api_req('POST', '/api/device/unlock', json.dumps({'pin': '2468'}), auth)[0], 201)
        self.assertEqual(self.maintenance_request()[0], 200)

    def test_maintenance_state_failure_does_not_grant_or_rotate(self):
        self.store.set_maintenance_password('A classroom maintenance phrase!')
        original = self.store.path.read_bytes()
        with patch('server.os.replace', side_effect=OSError('disk full')):
            self.assertEqual(self.maintenance_request()[0], 503)
            self.assertEqual(self.control_req('POST', '/maintenance-password', urlencode({
                'csrf': self.csrf(), 'action': 'set', 'maintenance_password': 'A different classroom phrase!'}))[0], 503)
        self.assertEqual(self.store.path.read_bytes(), original)
        self.assertEqual(self.store.data, json.loads(original))
        self.assertEqual(self.maintenance_request(password='A different classroom phrase!')[0], 403)
        self.assertEqual(self.maintenance_request()[0], 200)

    def test_maintenance_rotation_during_verification_invalidates_result(self):
        self.store.set_maintenance_password('A classroom maintenance phrase!')
        def verify_then_disable(*args):
            self.store.set_maintenance_password(None)
            return True
        with patch.object(self.store.maintenance_guard, 'verify', side_effect=verify_then_disable):
            self.assertEqual(self.maintenance_request()[0], 403)
        self.assertNotIn('maintenance_events', self.store.data)

    def test_invalid_maintenance_requests_are_rejected(self):
        valid = {'action': 'install', 'nonce': 'c'*64, 'maintenance_password': 'A classroom maintenance phrase!'}
        for item in [dict(valid, action='update'), dict(valid, nonce='short'), dict(valid, maintenance_password=1),
                     dict(valid, extra='ignored'), {'action': 'install'}]:
            with self.subTest(item=item):
                self.assertEqual(self.api_req('POST', '/api/maintenance/authorize', json.dumps(item))[0], 400)
        raw = json.dumps(valid)
        for malformed in [raw[:-1] + ',"action":"install"}',
                          raw[:-1] + ',"\\u0061ction":"uninstall"}',
                          raw.encode('utf-16'), raw+' '*2048]:
            self.assertEqual(self.api_req('POST', '/api/maintenance/authorize', malformed)[0], 400)
        self.store.set_maintenance_password('A classroom maintenance phrase!')
        self.assertEqual(self.maintenance_request(password='a'*12+'\ud800')[0], 403)
        self.store.data['maintenance_credential'] = 'corrupt record'
        self.assertEqual(self.maintenance_request()[0], 403)

    def test_invalid_unicode_does_not_poison_device_state(self):
        payload = {'id': 'X'*24, 'key': 'Y'*32, 'name': '\ud800'}
        self.assertEqual(self.api_req('POST', '/api/device/register', json.dumps(payload))[0], 400)
        self.assertNotIn(payload['id'], self.store.data['devices'])
        self.assertEqual(self.control_req('GET', '/')[0], 200)
        auth = self.approved_device()
        for kind, obj, label in [('application', 'a'*64, '\udfff'), ('local_html', '\ud800', '')]:
            with self.subTest(kind=kind):
                self.assertEqual(self.api_req('POST', '/api/device/request',
                    json.dumps({'kind': kind, 'object': obj, 'label': label}), auth)[0], 400)
        self.assertEqual(self.store.data['requests'], [])

    def test_non_ascii_csrf_is_rejected(self):
        self.assertEqual(self.control_req('POST', '/policy', urlencode({'csrf': '错误'}))[0], 403)

    def test_idle_tls_peer_does_not_block_api(self):
        with socket.create_connection(('127.0.0.1', self.api.server_port), timeout=5):
            self.assertEqual(self.api_req('GET', '/health')[0], 200)

    def test_connection_limit_and_idle_timeout_release_worker(self):
        started, released = threading.Event(), threading.Event()
        class TrackedHandler(Handler):
            def setup(self):
                super().setup()
                started.set()
        class TrackedServer(TeacherHTTPServer):
            def process_request_thread(self, *args):
                try:
                    super().process_request_thread(*args)
                finally:
                    released.set()
        with TrackedServer(('127.0.0.1', 0), TrackedHandler, max_workers=1) as server:
            server.request_timeout = 2
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                address = server.server_address
                with socket.create_connection(address, timeout=5) as idle:
                    self.assertTrue(started.wait(5))
                    with socket.create_connection(address, timeout=5) as rejected:
                        try:
                            self.assertEqual(rejected.recv(1), b'')
                        except ConnectionResetError:
                            pass
                    self.assertEqual(idle.recv(1), b'')
                self.assertTrue(released.wait(5))
                connection = http.client.HTTPConnection(*address, timeout=5)
                try:
                    connection.request('GET', '/health')
                    response = connection.getresponse()
                    self.assertEqual(response.status, 200)
                    response.read()
                finally:
                    connection.close()
            finally:
                server.shutdown()
                thread.join(timeout=5)

    def test_truncated_body_and_deep_json_are_rejected(self):
        with socket.create_connection(('127.0.0.1', self.control.server_port), timeout=5) as peer:
            peer.sendall(b'POST /policy HTTP/1.0\r\nHost: 127.0.0.1\r\nContent-Length: 10\r\n\r\nxx')
            peer.shutdown(socket.SHUT_WR)
            with peer.makefile('rb') as response:
                self.assertIn(b' 413 ', response.readline())
        self.assertEqual(self.api_req('POST', '/api/device/register',
            '['*2000 + '0' + ']'*2000)[0], 400)

    def test_control_bind_failure_releases_api_port(self):
        created = []
        def make_server(*args, **kwargs):
            server = TeacherHTTPServer(*args, **kwargs)
            created.append(server)
            return server
        with socket.socket() as occupied:
            occupied.bind(('127.0.0.1', 0))
            occupied.listen()
            with patch('server.TeacherHTTPServer', side_effect=make_server):
                with self.assertRaises(OSError):
                    root = Path(self.temp.name)
                    serve_teacher(self.store.path, root/'cert.pem', root/'key.pem',
                                  '127.0.0.1', 0, control_port=occupied.getsockname()[1])
        self.assertEqual(len(created), 1)
        self.assertEqual(created[0].socket.fileno(), -1)

    def test_retried_requests_are_idempotent_even_at_capacity(self):
        auth = self.approved_device()
        body = json.dumps({'kind': 'website', 'object': 'game.example'})
        status, _, result = self.api_req('POST', '/api/device/request', body, auth)
        self.assertEqual(status, 201)
        request_id = json.loads(result)['id']
        for _ in range(3):
            status, _, result = self.api_req('POST', '/api/device/request', body, auth)
            self.assertEqual(status, 201)
            self.assertEqual(json.loads(result)['id'], request_id)
        self.assertEqual(len(self.store.data['requests']), 1)
        with self.store.lock:
            self.store.data['requests'].extend(
                dict(id=str(i), device_id='other', kind='website', object='other.example',
                     state='pending', created=1) for i in range(9999))
        self.assertEqual(self.api_req('POST', '/api/device/request', body, auth)[0], 201)
        self.assertEqual(self.api_req('POST', '/api/device/request',
            json.dumps({'kind': 'website', 'object': 'new.example'}), auth)[0], 429)
        with self.store.lock:
            self.store.data['requests'][1]['state'] = 'denied'
        self.assertEqual(self.api_req('POST', '/api/device/request',
            json.dumps({'kind': 'website', 'object': 'new.example'}), auth)[0], 201)
        self.assertEqual(len(self.store.data['requests']), 10000)
        self.assertEqual(self.store.data['requests'][0]['id'], request_id)

    def test_repeated_unlock_renews_one_grant(self):
        auth = self.approved_device()
        self.store.set_unlock_pin('2468')
        for _ in range(3):
            self.assertEqual(self.api_req('POST', '/api/device/unlock',
                json.dumps({'pin': '2468'}), auth)[0], 201)
        self.assertEqual(len(self.store.data['requests']), 1)

    def test_upgrade_compacts_duplicate_pending_history(self):
        original = dict(id='first', device_id='old-device', kind='application',
                        object='a'*64, state='pending', created=1)
        self.store.data['requests'] = [original, dict(original, id='latest'),
                                      dict(original, id='denied', state='denied')]
        self.store.save()
        loaded = Store(self.store.path)
        self.assertEqual([item['id'] for item in loaded.data['requests']], ['latest', 'denied'])
        self.assertEqual(json.loads(self.store.path.read_text('utf-8'))['requests'],
                         loaded.data['requests'])

    def test_failed_policy_save_rolls_back_and_can_retry(self):
        original = self.store.path.read_bytes()
        body = urlencode({'csrf': self.csrf(), 'domains': 'new.example', 'hashes': '', 'names': ''})
        with patch('server.os.replace', side_effect=OSError('disk unavailable')):
            self.assertEqual(self.control_req('POST', '/policy', body)[0], 503)
        self.assertEqual(self.store.path.read_bytes(), original)
        self.assertEqual(self.store.data, json.loads(original))
        self.assertEqual(list(self.store.path.parent.glob('.ohno-*')), [])
        self.assertEqual(self.control_req('POST', '/policy', body)[0], 303)
        self.assertEqual(self.store.data['web_domains'], ['new.example'])
        self.assertEqual(self.store.data['policy_revision'], 1)

    def test_failed_registration_save_does_not_create_phantom_device(self):
        payload = json.dumps({'id': 'Z'*24, 'key': 'Y'*32, 'name': 'new-pc'})
        original = self.store.path.read_bytes()
        with patch('server.tempfile.mkstemp', side_effect=OSError('disk full')):
            self.assertEqual(self.api_req('POST', '/api/device/register', payload)[0], 503)
        self.assertEqual(self.store.data, json.loads(original))
        self.assertEqual(self.store.path.read_bytes(), original)
        self.assertEqual(self.api_req('POST', '/api/device/register', payload)[0], 201)

    def test_failed_pin_save_does_not_enable_unpersisted_pin(self):
        body = urlencode({'csrf': self.csrf(), 'action': 'set', 'pin': '2468'})
        with patch('server.os.fsync', side_effect=OSError('disk full')):
            self.assertEqual(self.control_req('POST', '/unlock-pin', body)[0], 503)
        self.assertIsNone(self.store.data['unlock_pin_hash'])
        self.assertFalse(self.store.verify_unlock_pin('2468', 'test'))

    def test_management_is_loopback_only_and_passwordless(self):
        self.assertEqual(self.api_req('GET','/')[0],404)
        self.assertEqual(self.api_req('GET','/school-installer')[0],404)
        self.assertEqual(self.control_req('POST','/api/device/register','{}')[0],404)
        status,_,page=self.control_req('GET','/')
        self.assertEqual(status,200)
        self.assertIn('仅本机可管理',page)
        self.assertNotIn('action="/login"',page)
        self.assertNotIn('name="password"',page)
        self.assertEqual(self.control_req('GET','/',headers={'Host':'evil.example'})[0],404)
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

    def test_legacy_management_password_hash_is_removed(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'legacy.json'
            legacy={'version':1,'salt':'00'*16,'password_hash':'deadbeef',
                    'policy_revision':0,'web_domains':[],'program_hashes':[],
                    'program_names':[],'block_local_files':False,'devices':{},'requests':[]}
            path.write_text(json.dumps(legacy),encoding='utf-8')
            loaded=Store(path)
            self.assertIsNone(loaded.data['unlock_pin_hash'])
            saved=json.loads(path.read_text('utf-8'))
            self.assertNotIn('salt',saved)
            self.assertNotIn('password_hash',saved)

    def test_state_no_overwrite(self):
        with self.assertRaises(FileExistsError):Store.initialize(self.store.path)


if __name__ == '__main__': unittest.main()
