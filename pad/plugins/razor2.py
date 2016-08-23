import pad.plugins.base
import subprocess
from threading import Timer


class Razor2Plugin(pad.plugins.base.BasePlugin):
    eval_rules = ("check_razor2",)

    options = {"use_razor2": ("bool", True),
               "razor_timeout": ("int", 10),
               "razor_config": ("str", "")
               }

    def check_razor2(self, msg, full = "", target = None):
        try:
            # import pdb;
            # pdb.set_trace()
            return self.get_local(msg, "razor2_result")

        except KeyError:
            print("exception in get_local\n")
            self.set_local(msg, "razor2_result", 0)

            if not self["use_razor2"]:
                return 0

            try:
                if self["razor_config"] == "":
                    proc = subprocess.Popen(["razor-check"],
                                            stderr=subprocess.PIPE, stdin=subprocess.PIPE,
                                            stdout=subprocess.PIPE)
                else:
                    proc = subprocess.Popen(["razor-check", self["razor_config"]],
                                            stderr=subprocess.PIPE, stdin=subprocess.PIPE,
                                            stdout=subprocess.PIPE)
                    my_timer = Timer(self["razor_timeout"], proc.kill(), [proc])
            except ValueError:
                self.ctxt.log.err("Unable to run the subprocess")
            except OSError:
                self.ctxt.log.warning("Unable to run razor-check")

            try:
                std_out, std_err = proc.communicate(input=str.encode(msg.raw_msg))
                # self.set_local(msg, "razor2_result", std_out)
            except (TimeoutError, subprocess.TimeoutExpired):
                self.ctxt.log.debug("Razor timed out")
                proc.kill()
                std_out, std_err = proc.communicate()

            self.set_local(msg, "razor2_result", std_out)

            if proc.returncode is None:  # nu s-a terminat procesul copil
                proc.terminate()

            # return code = 1 => not a spam
            return proc.returncode

    def plugin_report(self, msg):
        """Report the digest to razor as spam."""
        try:
            proc = subprocess.Popen(["razor-revoke"],
                                    stderr=subprocess.PIPE,
                                    stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE)
            my_timer = Timer(self["razor_timeout"], proc.kill(), [proc])
            std_out, std_err = proc.communicate(input=str.encode(msg.raw_msg))
            return proc.returncode

        except subprocess.CalledProcessError as e:
            self.ctxt.log.warning("Unable to run check_output()")
            return e.returncode
        except TimeoutError:
            self.ctxt.log.warning("Timeout Error")
        except OSError:
            self.ctxt.log.warning("Unable to run razor-report")

        return False

    def plugin_revoke(self, msg):
        """Report the digest to razor as ham."""
        try:
            proc = subprocess.Popen("razor-revoke",
                                    stderr=subprocess.PIPE,
                                    stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE)
            my_timer = Timer(self["razor_timeout"], proc.kill(), [proc])
            std_out, std_err = proc.communicate(input=str.encode(msg.raw_msg))
            return proc.returncode

        except subprocess.CalledProcessError as e:
            self.ctxt.log.warning("Unable to run check_output()")
            return e.returncode
        except TimeoutError:
            self.ctxt.log.warning("Timeout Error")
        except OSError:
            self.ctxt.log.warning("Unable to run razor-revoke")

        return False