import os
import pathlib
import tempfile
import unittest
from unittest.mock import patch
import runtime_paths


class PortableRuntimeTests(unittest.TestCase):
    def test_packaged_engine_never_falls_back_to_machine_homebrew(self):
        with patch.object(runtime_paths,'bundle_contents',return_value=pathlib.Path('/Example.app/Contents')):
            self.assertEqual(runtime_paths.engine_paths('openvpn'),('/Example.app/Contents/Helpers/openvpn',))
            self.assertEqual(runtime_paths.engine_paths('sing-box'),('/Example.app/Contents/Helpers/sing-box',))

    def test_runtime_environment_ignores_host_python_and_injected_dyld(self):
        with patch.object(runtime_paths,'bundle_contents',return_value=pathlib.Path('/Example.app/Contents')),patch.dict(os.environ,{'PYTHONPATH':'/untrusted','DYLD_LIBRARY_PATH':'/untrusted','__PYVENV_LAUNCHER__':'/other-python'},clear=True):
            env=runtime_paths.runtime_environment()
            self.assertNotIn('PYTHONPATH',env)
            self.assertNotIn('DYLD_LIBRARY_PATH',env)
            self.assertNotIn('__PYVENV_LAUNCHER__',env)
            self.assertEqual(env['PYTHONHOME'],'/Example.app/Contents/Frameworks/Python.framework/Versions/3.14')

    def test_bundled_python_disables_site_and_bytecode_writes(self):
        with patch.object(runtime_paths,'bundle_contents',return_value=pathlib.Path('/Example.app/Contents')):
            command=runtime_paths.python_command('app.py','/test.sock')
            self.assertEqual(command[1:4],['-B','-s','-S'])

    def test_arbitrary_engine_name_rejected(self):
        with self.assertRaises(ValueError):runtime_paths.engine_paths('../unexpected')
