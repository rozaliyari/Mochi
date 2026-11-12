import unittest
from unittest.mock import Mock,patch
import desktop_launch
import desktop_bootstrap


class DesktopLifecycleTests(unittest.TestCase):
    def test_normal_dashboard_exit_shuts_down_its_helper(self):
        child=Mock();child.wait.return_value=0;child.poll.return_value=0
        with patch.object(desktop_launch.subprocess,'Popen',return_value=child),patch.object(desktop_launch.signal,'signal'),patch.object(desktop_launch,'rpc') as rpc:
            self.assertEqual(desktop_launch.run('/test/control.sock'),0)
            rpc.assert_called_once_with('/test/control.sock',{'op':'shutdown'})
            child.terminate.assert_not_called()

    def test_application_termination_cleans_up_helper_and_child(self):
        child=Mock();child.wait.side_effect=[KeyboardInterrupt(),0];child.poll.return_value=None
        with patch.object(desktop_launch.subprocess,'Popen',return_value=child),patch.object(desktop_launch.signal,'signal'),patch.object(desktop_launch,'rpc') as rpc:
            self.assertEqual(desktop_launch.run('/test/control.sock'),0)
            rpc.assert_called_once_with('/test/control.sock',{'op':'shutdown'})
            child.terminate.assert_called_once()

    def test_privileged_bootstrap_rejects_unapproved_executable(self):
        with patch.object(desktop_bootstrap.os,'geteuid',return_value=0),patch.object(desktop_bootstrap.sys,'argv',['bootstrap','501','123','/tmp/unapproved']),patch.object(desktop_bootstrap.subprocess,'Popen') as spawn:
            with self.assertRaisesRegex(RuntimeError,'Invalid launch settings'):desktop_bootstrap.main()
            spawn.assert_not_called()
