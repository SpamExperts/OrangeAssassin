import unittest
import subprocess
import time

try:
    from unittest.mock import patch, Mock, MagicMock, call
except ImportError:
    from mock import patch, Mock, MagicMock, call

import pad.plugins.razor2

class TestRazor2(unittest.TestCase):
    def setUp(self):
        unittest.TestCase.setUp(self)
        self.options = {}
        self.global_data = {}
        self.msg_data = {}

        self.mock_ctxt = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.global_data[k],
            "set_plugin_data.side_effect": lambda p, k, v: self.global_data.
                                   setdefault(k, v)}
        )
        self.mock_msg = MagicMock(**{
            "get_plugin_data.side_effect": lambda p, k: self.msg_data[k],
            "set_plugin_data.side_effect": lambda p, k, v: self.msg_data.
                                  setdefault(k, v),
        })
        self.mock_msg.raw_msg = "testmessage"

        self.mock_subprocess_Popen = patch(
            "pad.plugins.razor2.subprocess.Popen").start()

        # self.mock_communicate = patch(
        #     "pad.plugins.razor2.subprocess.Popen.communicate").start()

        self.plug = pad.plugins.razor2.Razor2Plugin(self.mock_ctxt)

    def tearDown(self):
        unittest.TestCase.tearDown(self)
        patch.stopall()

    def test_check_razor2_no_use(self):
        self.global_data["use_razor2"] = False
        result = self.plug.check_razor2(self.mock_msg)
        self.assertEqual(result, 0)

    def test_check_razor2_get_cache(self):
        self.plug.set_local(self.mock_msg, "razor2_result", 1)
        self.global_data["use_razor2"] = True
        result = self.plug.check_razor2(self.mock_msg)
        self.assertEqual(result, 1)

    def test_check_razor2_no_config_file(self):
        self.global_data["use_razor2"] = True
        self.global_data["razor_config"] = ""
        proc_obj = self.mock_subprocess_Popen.return_value
        proc_obj.returncode = 0
        result = self.plug.check_razor2(self.mock_msg)
        self.mock_subprocess_Popen.assert_called_with(
            ["razor-check"], stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE)
        self.assertEqual(result, 1)

    def test_check_razor2_config_file(self):
        self.global_data["use_razor2"] = True
        self.global_data["razor_config"] = "config_file.cf"
        proc_obj = self.mock_subprocess_Popen.return_value
        proc_obj.returncode = 0
        result = self.plug.check_razor2(self.mock_msg)
        self.mock_subprocess_Popen.assert_called_with(
            ["razor-check", "-conf=config_file.cf"], stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE)
        self.assertEqual(result, 1)

    def test_check_razor2_OSError(self):
        self.global_data["use_razor2"] = True
        self.global_data["razor_config"] = "config_file.cf"
        self.mock_subprocess_Popen.side_effect = OSError
        result = self.plug.check_razor2(self.mock_msg)
        self.assertEqual(result, None)

    def test_plugin_report_returncode(self):
        proc_obj = self.mock_subprocess_Popen.return_value
        proc_obj.returncode = 1
        result = self.plug.plugin_report(self.mock_msg)
        self.assertEqual(result, 1)

    def test_plugin_report_OSError(self):
        self.mock_subprocess_Popen.side_effect = OSError
        result = self.plug.plugin_report(self.mock_msg)
        self.assertEqual(result, None)

    def test_plugin_report_config_file(self):
        self.global_data["razor_config"] = "config_file.cf"
        proc_obj = self.mock_subprocess_Popen.return_value
        proc_obj.returncode = 1
        result = self.plug.plugin_report(self.mock_msg)
        self.mock_subprocess_Popen.assert_called_with(
            ["razor-report", "-conf=config_file.cf"], stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE)
        self.assertEqual(result, 1)

    def test_plugin_revoke_returncode(self):
        proc_obj = self.mock_subprocess_Popen.return_value
        proc_obj.returncode = 1
        result = self.plug.plugin_revoke(self.mock_msg)
        self.assertEqual(result, 1)

    def test_plugin_revoke_OSError(self):
        self.mock_subprocess_Popen.side_effect = OSError
        result = self.plug.plugin_revoke(self.mock_msg)
        self.assertEqual(result, None)

    def test_plugin_revoke_timer(self):
        mock_kill_process = patch(
            "pad.plugins.razor2.kill_process").start()
        self.global_data["razor_timeout"] = 1
        proc_obj = self.mock_subprocess_Popen.return_value
        result = self.plug.plugin_revoke(self.mock_msg)
        mock_kill_process.assert_not_called()

    def test_plugin_revoke_config_file(self):
        self.global_data["razor_config"] = "config_file.cf"
        proc_obj = self.mock_subprocess_Popen.return_value
        proc_obj.returncode = 1
        result = self.plug.plugin_revoke(self.mock_msg)
        self.mock_subprocess_Popen.assert_called_with(
            ["razor-revoke", "-conf=config_file.cf"], stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE)
        self.assertEqual(result, 1)

    def wait_proc(self, *args, **kwargs):
        return time.sleep(5)

    def test_plugin_revoke_time_exceeded(self):
        mock_kill_process = patch(
            "pad.plugins.razor2.kill_process").start()
        self.global_data["razor_timeout"] = 1
        proc_obj = self.mock_subprocess_Popen.return_value
        proc_obj.returncode = 1
        proc_obj.communicate = self.wait_proc
        result = self.plug.plugin_revoke(self.mock_msg)
        mock_kill_process.assert_called_with(proc_obj, self.mock_ctxt.log)

    def test_plugin_report_OSError_communicate(self):
        proc_obj = self.mock_subprocess_Popen.return_value
        proc_obj.communicate.side_effect = OSError
        result = self.plug.plugin_report(self.mock_msg)
        self.assertEqual(result, False)

    def test_plugin_revoke_OSError_communicate(self):
        proc_obj = self.mock_subprocess_Popen.return_value
        proc_obj.communicate.side_effect = OSError
        result = self.plug.plugin_revoke(self.mock_msg)
        self.assertEqual(result, False)


def suite():
    """Gather all the tests from this package in a test suite."""
    test_suite = unittest.TestSuite()
    return test_suite


if __name__ == '__main__':
    unittest.main(defaultTest='suite')
