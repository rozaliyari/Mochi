import json
import os
import pathlib
import socket
import tempfile
import unittest
from tray_control import TrayControl


class TrayControlTests(unittest.TestCase):
    def setUp(self):
        self.folder=tempfile.TemporaryDirectory(dir='/tmp');self.path=pathlib.Path(self.folder.name)/'control.sock'
        self.channel=TrayControl(self.path)
    def tearDown(self):self.channel.close();self.folder.cleanup()
    def send(self,message):
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(3);client.connect(str(self.path));client.sendall((json.dumps(message)+'\n').encode())
            return json.loads(client.makefile('rb').readline())
    def test_actions_target_stable_profile_ids_without_credentials(self):
        message=dict(op='connect',id='a'*32)
        self.assertTrue(self.send(message)['ok'])
        self.assertEqual(self.channel.commands.get_nowait(),message)
        for bad in [dict(op='connect',id='bad'),dict(op='connect',id='a'*32,password='secret'),dict(op='shutdown'),dict(op='run',path='/tmp/script')]:
            self.assertFalse(self.send(bad)['ok'])
    def test_private_socket_and_minimal_state_permissions(self):
        self.assertEqual(os.stat(self.path).st_mode&0o777,0o600)
        self.channel.publish([dict(id='a'*32,name='Example',state='connected',password='never-export',log='never-export')])
        path=self.path.with_name('state.json')
        self.assertEqual(os.stat(path).st_mode&0o777,0o600)
        data=json.loads(path.read_text());self.assertEqual(set(data['profiles'][0]),{'id','name','state'})
        self.assertNotIn('never-export',path.read_text())
    def test_unchanged_state_keeps_liveness_heartbeat(self):
        self.channel.publish([]);path=self.path.with_name('state.json')
        os.utime(path,(1,1));self.channel.last_heartbeat=0
        self.channel.publish([]);self.assertGreater(path.stat().st_mtime,1)
    def test_unsafe_public_directory_is_refused(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as folder:
            os.chmod(folder,0o755)
            with self.assertRaisesRegex(ValueError,'Unsafe'):TrayControl(pathlib.Path(folder)/'control.sock')
