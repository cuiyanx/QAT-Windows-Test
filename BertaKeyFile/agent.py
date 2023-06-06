#!/usr/bin/env python
"""
This is the agent script for test automation target system.

The agent script is started by bootstrapping script and connects to the
controller script on server via xml-rpc. The agent script downloads a task
to execute, runs the task's tool on a mounted samba share and reports the
results to the controller script. Then it uploads the task result logs to the
samba share.

This script was ported from win_x86. Some code is retained for future back
porting to windows. This windows specific code is marked with "@PORT windows".
Some code may not be needed at all and is marked "@PORT not_used".
"""
from __future__ import print_function, division, absolute_import

import logging
import json
import os
try:
    import xmlrpc.client as xmlrpclib
except ImportError:
    import xmlrpclib
import re
import time
import shutil
import datetime
import glob            # for storing and deleting crash_*.txt
import fnmatch
import platform
import traceback

# Berta imports
import checks
import environment
import consts
from consts import AGENT_OS_CHECKED_FILE, AGENT_BUILD_DIR, AGENT_TASKS_DIR, AGENT_OS_EXT_IMAGER_FILE
from consts import AGENT_PREPARING_MACHINE, AGENT_SCRIPT_STARTED, AGENT_CONFIGURING_TASK, AGENT_STARTING_IMAGE_LOADER, AGENT_RUNNING_TASK
from consts import AGENT_COPYING_MEMDUMPS, AGENT_STORING_RESULTS, AGENT_REGISTRY_BACKUP, AGENT_WAITING_FOR_STORING_RESULTS
from consts import AGENT_INSTALLING_BUILD
from consts import TASK_CMPLT_ABANDONED, TASK_CMPLT_SCHEDULED_FOR_RE_RUN, TASK_CMPLT_SCHEDULED_FOR_CANCEL_AND_RE_RUN, TASK_CMPLT_AGENT_EXCEPTION
from consts import TASK_CMPLT_AGENT_MISSING_WRAPPER, TASK_CMPLT_AGENT_FINISHED, TASK_CMPLT_AGENT_TIMEOUT, TASK_CMPLT_AGENT_ERROR_RETURNED
from consts import TASK_CMPLT_AGENT_BUILD_INSTALL_ERROR, TASK_CMPLT_MISSING_OS, TASK_CMPLT_AGENT_BUILD_VERIFICATION_FAILED, TASK_CMPLT_AGENT_HW_ISSUE
from consts import TARGET_NO_REBOOT, TARGET_REBOOT, SERVER_ADDR_FILE
from consts import SYSTEM_DISK_FREE_SPACE_MAC, CACHE_DISK_FREE_SPACE_MAC
from data_utils import string_bool, filter_names_not_bad_endings
import utils
from utils import exec_with_timeout, RebootNeededError, ShutdownNeededError, FailedStartingXServerError, fread
from utils import str_join
import convert
from hwmonitor import HwMonitor
from wrappers.buildinstallers import finalize_build_install, get_current_build_id, get_current_tool_id
from reslog import generate_noresults
from baseagent import BaseAgent
from capability_detectors import dmidecode
from job import is_hardware_reboot_needed
import crashdumps
import kernel_cmdline
from py2py3 import PY2, ensure_str
import booting
import httphelper
from getaddr import get_srv_address

join = utils.join
log = logging.getLogger(__name__)

# currently running system
SYSTEM = ""

# Dictionary of supported products and their installer classes
from wrappers.buildinstallers import BuildInstaller
from wrappers.fakeinstaller import FakeInstaller
from wrappers.copyinstaller import CopyInstaller
from wrappers.gitsinstaller import GITSInstaller
from wrappers.gfxinstaller import GfxInstaller, DUTPrepare, DUTPrepareSafe, DUTPrepareDriverMerge
from wrappers.amdinstaller import AMDInstaller
from wrappers.nvidiainstaller import NVIDIAInstaller
PRODUCTS = dict(unittest=BuildInstaller,
                fake=FakeInstaller,
                copy=CopyInstaller,
                gits=GITSInstaller,
                ufo=GfxInstaller,
                ufoocl=GfxInstaller,
                gfx_drv=GfxInstaller,
                nvidia=NVIDIAInstaller,
                amd=AMDInstaller,
                DUTPrepare=DUTPrepare,
                DUTPrepareSafe=DUTPrepareSafe,
                DUTPrepareDriverMerge=DUTPrepareDriverMerge)


def get_build_installer(product_name):
    """Return a list of build installer classes for the specified product name
    """
    return PRODUCTS.get(product_name, None)


class AgentGeneric(BaseAgent):
    """
    This is an abstract class for Berta Agent.
    This agent runs tests on target system.
    """
    hw_monitor_enabled = True

    def __init__(self, controller_addr, dirs, repo, mode=BaseAgent.SERVER_AGENT_MODE, use_hw_monitor=None):
        super(AgentGeneric, self).__init__(controller_addr, dirs, repo, mode)
        self.reboot_flag = TARGET_NO_REBOOT
        self.BUILD_DEST_DIR = join(self.var_dir, AGENT_BUILD_DIR)  # downloaded builds are kept here
        self.BUILD_ID_FILE = None
        self.OS_CHECKED_FILE = join(self.var_dir, AGENT_OS_CHECKED_FILE)
        self.TASKS_DIR = join(self.var_dir, AGENT_TASKS_DIR)

        self.agent_name = "agent"
        self.target = None
        self.target_capabilities = {}
        self.wrapper_interpreters = {".py": "python"}

        # setup environment that is inherited by all invoked scripts and other programs
        os.environ["BERTA_OS"] = ensure_str(SYSTEM)
        python_path = os.environ.setdefault("PYTHONPATH", self.agent_dir)
        if self.agent_dir not in python_path:
            os.environ["PYTHONPATH"] = utils.str_join(os.pathsep, self.agent_dir, python_path)
        log.info("Trying pythonpath: %s ", os.environ["PYTHONPATH"])

        self.logs_search_paths = []
        self.products = []
        self._products_with_info = []
        self.reboot_on_hw_error = False
        self.clean_memory_dump = True

        if use_hw_monitor is not None:
            self.hw_monitor_enabled = use_hw_monitor

        # start HW monitor
        if self.hw_monitor_enabled:
            self.hw_monitor = HwMonitor()
            self.hw_monitor.start()
        else:
            log.info("HW monitor is turned off.")

        if self.mode == self.SERVER_AGENT_MODE:
            self.is_multiboot = booting.is_multiboot()
            self.is_omapi_pxeboot = booting.is_omapi_pxeboot()
            self.is_dispatcher_pxeboot = booting.is_dispatcher_pxeboot()
            self.is_external_imager = checks.is_macos_ext_imager()
        else:
            self.is_multiboot = False
            self.is_omapi_pxeboot = False
            self.is_dispatcher_pxeboot = False

        if not self.is_multiboot and self.mode == self.SERVER_AGENT_MODE:
            # next time will boot to target
            if not checks.is_multiagent():
                booting.set_boot_to_target_once()
        self.machine_id = None
        self.logs_quota = 0
        self.dest_wrappers = "wrappers/"
        self.dest_modules = "./"

    def _get_interpreter(self, filepath):
        """ return a path to suitable interpreter to run wrapper or the file. """
        try:
            return self.wrapper_interpreters[os.path.basename(filepath)]
        except KeyError:
            pass
        for ext, path in self.wrapper_interpreters.items():
            if filepath.endswith(ext):
                return path
        log.warning("Cannot find interpreter for %s", filepath)
        return None

    def shutdown(self):
        if self.hw_monitor_enabled:
            self.hw_monitor.stop_running()
        super(AgentGeneric, self).shutdown()

    def write_some_task_log(self, filename, task, txt):
        fname = join(task.get_dir(), filename)
        if not txt.endswith("\n"):
            txt += "\n"
        utils.fwrite(fname, txt)

    def write_task_error(self, task, txt):
        self.write_some_task_log("agent_error.txt", task, txt)

    def get_current_build_id(self):
        """ Gets build id written to BUILD_ID_FILE. Build id should be unique. """
        return get_current_build_id(self.BUILD_ID_FILE)

    def get_current_tool_id(self):
        """ Gets tool id written to BUILD_ID_FILE. Tool id should be unique. """
        return get_current_tool_id(self.BUILD_ID_FILE)

    def prepare_machine(self):
        """
        This method is run only once at Agent startup. It is not called
        afterwards during normal operation. Exception to this is Agent
        update when Agent is restarted.

        This method is extended in derived classes with system specific code.
        """

        self.send_alive(AGENT_PREPARING_MACHINE)

        if not self.is_manual_mode():
            self.get_machine_info()
            self.detect_capabilities()
        else:
            log.info("Manual mode of agent detected. Capabilities detection disabled")

        log.info("Detected hardware:")
        for k, v in self.target_capabilities.items():
            log.info("\t%-20s: %s", k, v)

        build_id = -1

        # Find newest build-id*.txt file in BUILD_DEST_DIR directory to detect current installed build
        build_id_files = []
        if os.path.exists(self.BUILD_DEST_DIR):
            build_id_files = [join(self.BUILD_DEST_DIR, f)
                              for f in os.listdir(self.BUILD_DEST_DIR)
                              if re.compile("^build_id\S+.txt").match(f)]
        if build_id_files:
            log.info("Found build installed on target")
            self.BUILD_ID_FILE = max(build_id_files, key=os.path.getmtime)

        if not self.is_manual_mode() and self.BUILD_ID_FILE:
            build_id = self.get_current_build_id()

        self.target = self.server.configure_target(self.mac_address, SYSTEM,
                                                   build_id,
                                                   self.target_capabilities)

        log.info("Agent name: %s", self.target['name'])
        current_time = datetime.datetime.strptime(self.target['current_time'].value, "%Y%m%dT%H:%M:%S")

        if not self.disable_timesync:
            log.info("Setting time to %s", current_time)
            utils.set_time(current_time)
        else:
            log.info("Timesync disabled.")

        self.machine_id = self.target.get('machine_id', None)
        if not self.machine_id:
            log.info("Manual mode of agent detected. Setting machine_id disabled.")

        # Share is mounted and unmounted by bootstrap, here it's just a sanity check
        if self.is_offline_manual_mode():
            log.info("Agent is in offline manual mode, no possibility of mounting share")
        elif self._ensure_mount():
            pass
        elif self.is_manual_mode():
            log.warning("Berta samba is not mounted on this machine, you may have problems with some tests")
        else:
            raise Exception("Mounting samba share failed %s" % self.srv_addr["smb"])

        for d in [self.BUILD_DEST_DIR, self.TASKS_DIR]:
            if not os.path.isdir(d):
                os.makedirs(d)

        if self.is_multiboot and self.mode == self.SERVER_AGENT_MODE:
            # set current system as default to boot to
            msg = booting.set_multib_entry(SYSTEM, self.target['system_name'])
            if msg:
                log.error(msg)

        os.environ['BERTA_MACHINE_NAME'] = self.target.get('name', '')
        os.environ['BERTA_MACHINES_GROUP_NAME'] = self.target.get('machines_group_name', '')
        self.logs_quota = self.target.get('task_logs_quota', 0)
        log.info("Agent started")
        self.send_alive(AGENT_SCRIPT_STARTED)

    def _ensure_mount(self):
        try:
            self.repo.ensure_mount(self.srv_addr)
        except:
            return False
        return True

    def _prev_task_cleanup(self, current_task_id=None):
        log.info("cleaning any previous tasks, current task id: %s", current_task_id)
        folders = os.listdir(self.TASKS_DIR)
        tasks = []
        # Exclude current task directory and all non-numeric directories first
        for f in folders:
            if current_task_id and f == current_task_id:
                crashdumps.after_reset_dumps_check(join(self.TASKS_DIR, f), int(f))
                continue
            try:
                task_id = int(f)
                crashdumps.after_reset_dumps_check(join(self.TASKS_DIR, f), task_id)
                tasks.append(f)
            except:
                p = join(self.TASKS_DIR, f)
                log.info("path %s not recognized as task direcotory - removing it" % p)
                utils.rm_tree(p)
        # Potential abandoned tasks dirs found, process them
        if not tasks:
            return

        for f in self.server.abandoned_tasks(tasks):
            task_dir = join(self.TASKS_DIR, f)
            log.info("cleaning %s" % task_dir)

            # Send results only to the server from which the task came
            srv_file = os.path.join(task_dir, SERVER_ADDR_FILE)
            if os.path.exists(srv_file):
                srv_addr = fread(srv_file).strip()
                if not self.is_offline_manual_mode() and srv_addr != self.srv_addr['ip']:
                    log.info("task from different server %s != %s" % (srv_addr, self.srv_addr['ip']))
                    continue

            try:
                task = utils.Task.load_from_file(full_path=task_dir, check_existence=True)
            except:
                log.exception("Problem with reading task.json")
                task = None

            if not task:
                task = utils.Task({
                    'task_id': int(f),
                    'config': {},
                    'jobs': [{}],
                    'current_job': 0,
                    'task_dir': task_dir,
                    'start_time': datetime.datetime.now(),
                })

            if checks.is_android() and ("MCG" in checks.get_flavour_name_lx() or checks.is_android_fake()):
                dest_dir = self.repo.get_results_dir(task)
                if not os.path.exists(dest_dir):
                    os.makedirs(dest_dir)

            self._run_post_config_script(task)
            self._complete_task(task, TASK_CMPLT_ABANDONED, "completing abandoned task")
        self._reset_system_state()

        # Delete directories belonging to tasks not recognized by server
        for f in os.listdir(self.TASKS_DIR):
            if current_task_id and f == current_task_id:
                continue
            p = join(self.TASKS_DIR, f)
            log.info("path %s belongs to unrecognized task - removing it", p)
            try:
                utils.rm_tree(p)
            except Exception as e:
                log.warning("Could not delete files from previous task.\n%s", e.message)

    def _configure_task(self, task):
        """ This method is expanded in AgentLinux and AgentWindows. This method gets all config vectors, with config_pre_action
        and config_post_action in name and creates files. It allows to fire several scripts as pre-action and post_action.
        To vectors cannot have the same names!"""
        log.info("Configuring task")
        self.agent_status = AGENT_CONFIGURING_TASK

        pre_vectors_names = filter_names_not_bad_endings(task.config.keys(), 'config_pre_action', '_args', '_timeout')
        pre_vectors_names.sort()
        for v in pre_vectors_names:
            self._create_config_file(task, v)

        post_vectors_names = filter_names_not_bad_endings(task.config.keys(), 'config_post_action', '_args', '_timeout')
        post_vectors_names.sort()
        for v in post_vectors_names:
            self._create_config_file(task, v)

        self.reboot_on_hw_error = string_bool(task.config.get('reboot_on_hw_error', ""))
        self.clean_memory_dump = string_bool(task.config.get('clean_memory_dump', ""))

    def _run_pre_config_script(self, task):
        """This method allows to fire several pre_config scripts"""
        pre_vectors_names = filter_names_not_bad_endings(task.config.keys(), 'config_pre_action', '_args', '_timeout')
        pre_vectors_names.sort()
        for v in pre_vectors_names:
            self._run_config_script(task, v)

    def _run_post_config_script(self, task):
        """This method allows to fire several post_config scripts"""
        post_vectors_names = filter_names_not_bad_endings(task.config.keys(), 'config_post_action', '_args', '_timeout')
        post_vectors_names.sort()
        for v in post_vectors_names:
            self._run_config_script(task, v)

    def _create_config_file(self, task, vector_name):
        config_script = task.config.get(vector_name, '')
        if config_script == "":
            return

        try:
            config_script = str_join(" ", config_script, task.config[str_join('_', vector_name, "args")])
        except KeyError:
            pass

        timeout = 15 * 60
        try:
            timeout = int(task.config[str_join('_', vector_name, "timeout")])
        except KeyError:
            pass
        except:
            log.exception("reading timeout failed")
            raise

        filename = join(self.var_dir, "{0}.txt".format(vector_name))
        with open(filename, 'w') as config_file:
            config_file.write(config_script)
            config_file.write('\n')
            config_file.write(str(timeout))
            config_file.write('\n')
            log.info("Config file %s created", filename)

    def _read_config_file(self, vector_name):
        timeout = 15 * 60
        config_script = ""

        filename = join(self.var_dir, vector_name + ".txt")
        if not os.path.exists(filename):
            return config_script, timeout
        try:
            line_iter = utils.fread_by_line(filename)
            config_script = next(line_iter)
            timeout = int(next(line_iter))
            del line_iter  # close file by iterator
        except StopIteration:
            log.info("Wrong data in %s file. %s-config will not be executed", filename, timeout)
        except:
            log.info("Timeout in %s file seems to be corrupted. Using default value %s", filename, timeout)
        os.remove(filename)
        return config_script, timeout

    def _run_config_script(self, task, vector_name):
        config_script, timeout = self._read_config_file(vector_name)
        if config_script == "":
            return

        if "$CONFIGROOT" in config_script:
            config_script = config_script.replace("$CONFIGROOT", join(self.SHARE_MNT_POINT, "repository/tools/config"))
        elif "$TOOLDIR" in config_script:
            tool_path = None
            for j in task.jobs:
                if 'tool_path' in j:
                    tool_path = j['tool_path']
                    break
            config_script = config_script.replace("$TOOLDIR", tool_path)
        else:
            config_script = join(self.SHARE_MNT_POINT, "repository/tools/config", config_script)

        log.info("Running config script (%s-actions) with timeout %d: %s" % (vector_name, timeout, config_script))
        out, ret = exec_with_timeout(config_script, timeout, shell=True, tracing=True, cwd=task.get_dir())
        if "RebootNeededError" in out:
            raise RebootNeededError("Reboot requested by config vector!")
        if "ShutdownNeededError" in out:
            raise ShutdownNeededError("Hard reboot requested by config vector!")
        if ret != 0:
            msg = "Config script returned unexpected return code %d: %s" % (ret, out)
            log.warning(msg)
            raise Exception(msg)

        log.info("Completed %s-actions." % vector_name)

    def is_reload_os_needed(self, task):
        if string_bool(task.config.get('force_os_reload', "")):
            log.info("OS reload is forced by config.")
            return True
        if task.task.get('force_os_reload', False):
            log.info("OS reload is forced by ctrlreqs.")
            return True
        if task.submitted_by.startswith("rerun_") and string_bool(task.config.get("os_reload_on_rerun", "")):
            log.info("OS reload is forced by task rerun and config.")
            return True
        if utils.is_os_dirty(self.var_dir):
            log.info("OS reload because os is dirty.")
            return True
        if utils.kernel_cmdline_changed(self.var_dir) and not task.config.get('setup_kernel_cmdline', ""):
            log.info("OS reload because kernel command line changed.")
            return True
        return False

    def _reload_os_if_needed(self, task):
        if self._is_os_fresh():
            return
        if self.is_reload_os_needed(task):
            self._boot_to_imageloader()

    def _get_external_imager_params(self, task):
        if 'extra_params' not in task.as_dict():
            return None
        extra_params = task.get('extra_params')
        if extra_params is None:
            return None
        ext_imager = extra_params.get('external_os_imager', None)
        if ext_imager is None:
            return None
        return json.dumps(ext_imager)

    def _load_external_imager_params(self):
        file_path = os.path.join(self.var_dir, AGENT_OS_EXT_IMAGER_FILE)
        if not os.path.exists(file_path):
            return None

        with open(file_path, "r") as ext_img_file:
            ext_img_params = ext_img_file.read()
            if not ext_img_params:
                return None
            return ext_img_params

    def _store_external_imager_params(self, ext_img_params):
        file_path = os.path.join(self.var_dir, AGENT_OS_EXT_IMAGER_FILE)

        with open(file_path, "w") as ext_img_file:
            if ext_img_params is not None:
                ext_img_file.write(ext_img_params)

    def _call_external_imager(self, task, job):
        ext_img_params = self._get_external_imager_params(task)

        hostname = self.target_capabilities['hostname']
        ip_ext = utils.get_macos_nvram("berta-ext-imager")
        log.info("Calling XMLRPC request to %s about flashing %s to %s" % (ip_ext, hostname, job['system']))
        ext = xmlrpclib.ServerProxy('http://%s:8000' % ip_ext)

        response = None
        if ext_img_params is not None:
            response = ext.flash_os(hostname, job['system'], self.ip_addr, self.mac_address, ext_img_params)
        else:
            response = ext.flash_os(hostname, job['system'], self.ip_addr, self.mac_address)

        if 'OK' not in response:
            self._complete_task(task, TASK_CMPLT_MISSING_OS, response)
            raise Exception(response)

        time.sleep(120)
        return

    def _install_os(self, task, job):
        if self.is_dispatcher_pxeboot:
            set_boot_entry = booting.set_dispatcher_pxe_nextboot_system
        elif self.is_omapi_pxeboot:
            set_boot_entry = booting.set_omapi_pxe_nextboot_system
        elif self.is_external_imager:
            self._call_external_imager(task, job)
        elif self.is_multiboot:
            set_boot_entry = booting.set_multib_entry
        else:
            self.agent_status = AGENT_STARTING_IMAGE_LOADER
            self._boot_to_imageloader()
            return

        msg = set_boot_entry(job['system'], job['system_name'])
        if not msg:
            log.info("Changed boot entry to %s OS." % job['system'])
            raise RebootNeededError("Reboot Needed")
        elif 'not found' == msg:
            self._complete_task(task, TASK_CMPLT_MISSING_OS, "os %s not found on this machine" % job['system'])
            raise Exception("%s OS not found." % job['system'])
        else:
            self._complete_task(task, TASK_CMPLT_AGENT_EXCEPTION, "problem during os change:\n%s" % msg)
            raise Exception("Failed changing boot entry to %s OS." % job['system'])

    def _boot_to_imageloader(self):
        if booting.set_boot_to_imageloader():
            log.info("Changed boot entry to image loader OS.")
        else:
            log.error("Failed changing GRUB boot entry to image loader OS.")

        raise RebootNeededError("Reboot Needed")

    def run_job_callback(self, i, poll_period, txt, retcode):
        """
        This is a callback for exec_with_timeout. Return True if
        task execution is ok and False if the task needs to be killed.
        """

        if self.action_for_agent == "cancel":
            return False

        if self.mode in (self.SERVER_AGENT_MODE, self.SAFE_MODE):
            # write wrapper log to share folder
            dst_wrapper_log_path = join(self.repo.get_results_dir(self.task), "job_%d_log.txt" % self.task.current_job_idx)
            utils.sync_log(txt, dst_wrapper_log_path, False, dst_offset=self.wrapper_log_offset)

            # sync agent log to share folder
            if i % (60 / poll_period / 3) == 0:  # one sync log for 20 secs
                self.sync_task_log(self.task)

        # check HW monitor and reboot if not Windows
        if self.task.current_job["job_type"] == "test" and self.hw_monitor_enabled and \
                not self.hw_monitor.hw_ok and self.reboot_on_hw_error:
            if retcode == utils.RETCODE_RUNNING:
                msg = "%s\n%s\n%s\n\n\nlog:\n%s\n%s" \
                    % ("=" * 80,
                       "HW does not work properly:",
                       self.hw_monitor.hw_error,
                       "=" * 80,
                       txt)
                self.write_task_error(self.task, msg)
                raise RebootNeededError("Reboot Needed")
            else:
                return False

        return True

    def _run_test(self, task, job):
        self.agent_status = AGENT_RUNNING_TASK
        self.send_alive(AGENT_RUNNING_TASK)

        sut_job = task.get_sut_job()
        separator = "/" if sut_job['is_buildstore'] and sut_job['buildstore_type'] in [consts.BUILDSTORE_TYPE_HTTP,
                                                                                       consts.BUILDSTORE_TYPE_ARTIFACTORY] else os.sep
        bld_path = join(self.BUILD_DEST_DIR, sut_job['product'], self.repo.get_build_dir(sut_job).split(separator)[-1])

        job['bld_path'] = bld_path
        txt, retcode, exit_status = self._run_job(task, job)

        self.write_some_task_log("job_%d_last_log.txt" % job["job_id"], task, txt)

        if retcode == 0:
            log.info("Task %s completed" % str(task.get_id()))
            return TASK_CMPLT_AGENT_FINISHED, ""

        else:
            if retcode == utils.RETCODE_SPECIAL_STATUS:
                if "status" in exit_status:
                    msg = txt
                    task_state = exit_status["status"]
                elif "reboot" in exit_status:
                    # check if wrapper triggers off reboot. do reboot and resume task
                    self._raise_reboot_if_needed(exit_status)
                elif "new_os" in exit_status and exit_status["new_os"]:
                    if not self.is_safe_mode():
                        log.info('New OS requied: setting grub to imageloader')
                        booting.set_boot_to_imageloader()
                        raise RebootNeededError("Wrapper triggered off reboot.")
                    else:
                        msg = 'New OS requied: ignored in safe mode'
                        log.info(msg)
                        task_state = TASK_CMPLT_AGENT_ERROR_RETURNED
                else:
                    msg = "missing exit status"
                    task_state = TASK_CMPLT_AGENT_ERROR_RETURNED
            elif retcode == utils.RETCODE_TRIGGER_OFF_REBOOT:
                # wrapper triggers off reboot. do reboot and resume task
                if is_hardware_reboot_needed(task):
                    raise ShutdownNeededError("Wrapper triggered hardware reboot.")
                raise RebootNeededError("Wrapper triggered off reboot.")
            elif retcode == utils.RETCODE_RE_RUN_TASK:
                msg = "Wrapper requested task id: %d re-run.\n" % task.get_id()
                task_state = TASK_CMPLT_SCHEDULED_FOR_RE_RUN
            elif retcode == utils.RETCODE_CANCEL_AND_RE_RUN_TASK:
                msg = "Wrapper requested task id: %d to be canceled and re-run.\n" % task.get_id()
                task_state = TASK_CMPLT_SCHEDULED_FOR_CANCEL_AND_RE_RUN
            elif retcode == utils.RETCODE_TERMINATED:
                # the task exceeded the timeout and was killed
                msg = "task id: %d process killed due to timeout (%d min)" % (task.get_id(), job['timeout'])
                task_state = TASK_CMPLT_AGENT_TIMEOUT
            else:
                # task exited with non-zero retcode
                msg = "task id: %d exited with non-zero return code: %d" % (task.get_id(), retcode)
                task_state = TASK_CMPLT_AGENT_ERROR_RETURNED

            log.warning("\n%s\n%s\n\n\n%s", "=" * 80, msg, "=" * 80)
            msg = "%s\n%s\n\n\nlog:\n%s\n%s" % ("=" * 80, msg, "=" * 80, txt)
            self.write_task_error(task, msg)

            screenshot_file = join(task.get_dir(), "screenshot_%s_2.bmp" % (time.strftime("%Y_%m_%d_%H_%M_%S", time.localtime())))
            utils.screenshot(screenshot_file)

            self.reboot_flag = TARGET_REBOOT
            log.warning("Task error")
            return task_state, msg

    def _reset_system_state(self):
        if self.mode != self.SERVER_AGENT_MODE:
            return

    def _remove_file(self, f):
        """
            remove file
            input: file with full path, e.g. /tmp/some-file
        """
        try:
            os.remove(f)
        except OSError:
            log.error("Error remove file: %s", f)

    def run_service_job(self, task, job):
        if 'os-reload' in job['scenario']:
            if 'mark-as-dirty' in job['scenario']:
                # always boot to imageloader - even if system is supposed to be fresh
                log.info("Service task. System on this machine is marked as dirty.")
                result_dir = self.repo.get_results_dir(task)
                generate_noresults(result_dir)
                self.server.task_completed(self.mac_address, task.get_id(),
                                           xmlrpclib.Binary(b"System on this machine is marked as dirty."),
                                           TASK_CMPLT_AGENT_FINISHED)
                log.info("Rebooting to install correct system...")
                self._install_os(task, task.get_system_job())
            else:
                if 'new_os' not in job:
                    log.info('System is not fresh.')
                    if self.is_multiboot and fnmatch.fnmatch(SYSTEM, task.get_system_job()['system']):
                        log.info("Required system is installed: " + task.get_system_job()['system'])
                    else:
                        log.info("Service task. Changing OS...")
                        self._install_os(task, task.get_system_job())
                log.info("Service task. Completed OS reload.")
                result_dir = self.repo.get_results_dir(task)
                generate_noresults(result_dir)
                self.server.task_completed(self.mac_address, task.get_id(),
                    xmlrpclib.Binary(b"System on this machine reloaded."),
                    TASK_CMPLT_AGENT_FINISHED)
        elif job['scenario'] == 'dump-os':
            if not task.get_system_job()['system'].startswith("Android"):
                # clear var_dir
                log.debug("List dir of %s: %s", self.var_dir, os.listdir(self.var_dir))
                files_to_del = glob.glob("%s/*.txt" % self.var_dir)
                for f in files_to_del:
                    if os.path.basename(f) in ["mnt_point.txt", "skip_reg_backup.txt", "last_upgrade.txt"]:
                        continue
                    log.debug("Removing %s", f)
                    self._remove_file(f)

                # clear target.log
                f = glob.glob("%s/target.log" % self.var_dir)[0]
                self._remove_file(f)

                self._install_os(task, task.get_system_job())
            else:
                if task.get_system_job()['system'].startswith("Android"):
                    error = b"Unsupported system %s" % task.get_system_job()['system']
                else:
                    error = b"OS not ready to dump, did you create os_ready.txt file?"

                self.server.task_completed(self.mac_address, task.get_id(),
                                        xmlrpclib.Binary(error),
                                        TASK_CMPLT_AGENT_ERROR_RETURNED)
        elif job['scenario'] == 'switch-to-DEV-OS':
            booting.set_boot_to_dev_os('%s\n%s' % (self.server_addr['ip'], self.machine_id))
            generate_noresults(self.repo.get_results_dir(task))
            self.server.task_completed(self.mac_address, task.get_id(),
                        xmlrpclib.Binary(b"System on this machine switched."),
                        TASK_CMPLT_AGENT_FINISHED)
            raise RebootNeededError("Reboot Needed")
        else:
            self.run_test_job(task, job)

    def run_system_job(self, task, job):
        service_job = task.get_service_job()
        if service_job and 'dump-os' in service_job['scenario']:
            log.info("Warning: dump-os scenario. Skipping system job.")
            return

        if self._is_os_fresh():
            if service_job and 'os-reload' in service_job['scenario']:
                service_job['new_os'] = True

            ext_img_params = self._get_external_imager_params(task)
            self._store_external_imager_params(ext_img_params)
        else:
            log.info('OS is not fresh.')

        if self.mode in (self.MANUAL_MODE, self.SAFE_MODE) or job['system'] == 'fake':
            log.info("Warning: Agent in MANUAL or SAFE mode. Skipping system job.")
            return

        if self.graceful_reboot:
            # task still running and under control
            log.info('Skipping system change - task in progress.')
            return

        # On multiboot systems we sometimes don't want to care about the kernel, so we allow wildcard matching
        if booting.is_multiboot() and fnmatch.fnmatch(SYSTEM, job['system']):
            log.info("Current system: %s", SYSTEM)
        # wildcard matching when we want to skip the kernel version
        elif not fnmatch.fnmatch(SYSTEM, job['system']):
            log.info("Current system: %s", SYSTEM)
            # log.info("Installing required system: %s", job['system'])
            # self._install_os(task, task.get_system_job())
        elif self._get_external_imager_params(task) != self._load_external_imager_params():
            log.info("Installing with new parameters for external imager")
            self._install_os(task, task.get_system_job())

        if not self._is_os_fresh():
            self._reload_os_if_needed(task)

        if checks.is_linux() and task.config.get("setup_kernel_cmdline", ""):
            self._setup_kernel_cmdline(task)

        log.info("Required system is installed: %s", job['system'])
        with open(self.OS_CHECKED_FILE, 'w') as f:
            f.write('This OS image is not fresh.')  # TODO: convert to utils.fread

    def _setup_kernel_cmdline(self, task):
        command_line = task.config.get("setup_kernel_cmdline", "")
        kc = kernel_cmdline.KernelCmdLineCfg()

        if command_line and kc.require_change(command_line):
            log.info("New kernel command line: %s", command_line)
            kc.modify_cmdline(kernel_cmdline.KernelCmdLineCfg.ADD, command_line)
            log.info("Kernel command line modified! Rebooting")
            utils.touch_files(os.path.join(self.var_dir, consts.AGENT_KERNEL_CMDLINE_CHANGED))
            raise RebootNeededError()

    def _is_os_fresh(self):
        return not os.path.exists(self.OS_CHECKED_FILE)

    def _run_job(self, task, job):
        job_id = job['job_id']
        log.info("Scenario %s for job %d:", job['scenario'], job_id)

        if job["tool_configuration"]:
            log.info("Tool configuration %s for job %d:", job['tool_configuration'], job_id)

        task.dump_json()
        task_dir = task.get_dir()
        exit_json = join(task_dir, "exit.json")
        if os.path.exists(exit_json):
            try:
                os.remove(exit_json)
            except:
                log.exception("Unable to delete exit.json")

        # prepare wrapper path
        default_wrapper = job['product'] + '.py'
        wrapper_path = default_wrapper
        if job["wrapper_path"]:
            wrapper_path = job["wrapper_path"]
            if os.path.isdir(wrapper_path):
                wrapper_path = join(wrapper_path, default_wrapper)

        if not os.path.exists(wrapper_path) or 'wrappers' not in os.path.abspath(wrapper_path):
            wrapper_path = join(self.agent_dir, "wrappers", wrapper_path)
            if not os.path.exists(wrapper_path):
                txt = "cannot find wrapper %s" % wrapper_path
                return txt, utils.RETCODE_SPECIAL_STATUS, {'status': TASK_CMPLT_AGENT_MISSING_WRAPPER}

        wrapper_path = os.path.abspath(wrapper_path)
        log.info("Wrapper path:  %s", wrapper_path)
        cmd = "%s %s" % (self._get_interpreter(wrapper_path), wrapper_path)
        sut_job = task.get_sut_job()
        job_product = ensure_str(job['product'])

        # prepare additional arguments to wrapper passed via environment
        env = os.environ.copy()
        env.update({
            'BERTA_BUILD_COMMENT': ensure_str(sut_job['build_comment']),
            'BERTA_PRODUCT': job_product,
        })

        screenshot_file = join(task_dir, time.strftime("screenshot_%Y_%m_%d_%H_%M_%S.bmp", time.localtime()))

        # !!! RUN WRAPPER !!! (timeout in seconds)
        txt, retcode = exec_with_timeout(cmd, job['timeout'] * 60, shell=True,
                                         cwd=task.get_dir(), env=env,
                                         callback=self.run_job_callback,
                                         screenshot_file=screenshot_file,
                                         universal_newlines=True)
        if retcode not in [0, utils.RETCODE_SPECIAL_STATUS]:
            message_template = "%s wrapper exited with unexpected non-zero code. Check job_%s_log.txt file for logs"
            log.error(message_template, job_product, job_id)

        exit_status = {}
        if os.path.exists(exit_json):
            try:
                exit_status = utils.load_json_file(exit_json)
            except:
                log.exception("json loads exc ignored")

        return txt, retcode, exit_status

    def _skip_sut_job(self, task, job):
        if task.get_service_job():
            why = "Service Task"
        elif checks.is_android_fake():
            why = "Android Fake"
        elif self.is_manual_mode():
            why = "Manual Mode"
        else:
            return False

        log.info("%s - skipping SUT job", why)
        return True

    def _raise_reboot_if_needed(self, exit_status):
        if exit_status.get('reboot', False):
            if exit_status.get('hard_reboot', False):
                raise ShutdownNeededError("Shutdown Needed")
            raise RebootNeededError("Reboot Needed")

    def _copy_modules_from_tool_build(self, param_name, dst, job):
        match = re.search('{}=(\S+)'.format(param_name), job["tool_configuration"])
        if not match:
            return
        modules_path = os.path.join(job['tool_path'], match.group(1))

        if os.path.exists(modules_path):
            log.info('Copy modules from tool build (%s) to: %s', modules_path, dst)
            try:
                for filename in os.listdir(modules_path):
                    shutil.copy(os.path.join(modules_path, filename), dst)
            except Exception as e:
                log.exception('Exception occurred during copying modules from tool build (%s) to %s: %s', modules_path, dst, e)
                raise e
            log.info('Copied modules from tool build to: %s', dst)
        else:
            log.info('Modules not found in path: %s', modules_path)

    def _copy_modules_from_build(self, param_name, dst, job):
        match = re.search('{}=(\S+)'.format(param_name), job["tool_configuration"])
        if not match:
            return
        modules_path = match.group(1)
        modules_url = httphelper.urljoin(job["buildstore_path"],
                                         job["build_path"],
                                         modules_path)

        if httphelper.http_exists(modules_url):
            log.info('Copy modules from build to: %s (%s)', dst, modules_url)
            try:
                httphelper.http_copy_files(modules_url, dst)
            except Exception as e:
                log.exception('Exception occurred when copying modules from build (%s) to %s: %s', modules_url, dst, e)
                raise e
            log.info('Copied modules from build to: %s', dst)
        else:
            log.info('Modules not found in path: %s', modules_url)

    def run_sut_job(self, task, job):
        if self._skip_sut_job(task, job):
            return

        environment.dump_env(environment.PHASE_PRE_SUT, task)

        log.info("Run installer product: %s", job['product'])
        if re.compile("^Android(-\S*-|-)Fake").match(job['system']):
            log.info("Detected Android-Fake: checking for android version")
            if not checks.is_android():
                log.info("Installing required system: %s", job['system'])
                self._install_os(task, task.get_system_job())
            self._reload_os_if_needed(task)
        self.agent_status = AGENT_INSTALLING_BUILD

        product_build_dir = join(self.BUILD_DEST_DIR, job['product'])
        product_build_id_file = 'build_id-{0}.txt'.format(job['wrapper_path'])
        self.BUILD_ID_FILE = build_id_file = join(self.BUILD_DEST_DIR, product_build_id_file)
        if not os.path.isdir(product_build_dir):
            os.makedirs(product_build_dir)

        self._copy_modules_from_build('copy_wrappers_from_build', 'wrappers/', job)
        self._copy_modules_from_build('copy_modules_from_build', './', job)
        self._copy_modules_from_tool_build('copy_wrappers_from_tool_build', self.dest_wrappers, task.get_test_job())
        self._copy_modules_from_tool_build('copy_modules_from_tool_build', self.dest_modules, task.get_test_job())

        job.update({
            'build_dest_dir': product_build_dir,
            'build_id_file': build_id_file,
            'var_dir': self.var_dir,
        })
        txt, _, exit_status = self._run_job(task, job)  # TODO: check retcode

        environment.dump_env(environment.PHASE_POST_SUT, task)

        # exit_status now requests installing new os i.e. refreshing system
        log.debug('exit_status: %s', exit_status)
        if exit_status.get('new_os', False):
            self._install_os(task, task.get_system_job())

        if exit_status.get('mark_os_dirty', False):
            utils.mark_os_dirty(self.var_dir)

        if exit_status.get('successful', False):
            job['exit_status'] = exit_status
            self._post_install()
            self._raise_reboot_if_needed(exit_status)
            self.server.configure_target(self.mac_address, SYSTEM,
                                         self.get_current_build_id(), self.target_capabilities)
        else:
            txt_template = "installing build failed:\n%s\ninstalling log: \n%s"
            txt = txt_template % (exit_status.get('error', '-'), utils.remove_non_ascii(txt))
            log.warning(txt)
            if exit_status.get('hw_issue', False):
                self._complete_task(task, TASK_CMPLT_AGENT_HW_ISSUE, txt)
            else:
                self._complete_task(task, TASK_CMPLT_AGENT_BUILD_INSTALL_ERROR, txt)
            self._reset_system_state()
            self._raise_reboot_if_needed(exit_status)
            raise Exception("Build installation failed. No Reboot.")

        # Clear build install iteration logs and print summary
        finalize_build_install(join(self.var_dir, "build_install.txt"))

    def _post_install(self):
        log.info("Build installed.")

    def run_test_job(self, task, job):
        task_dir = task.get_dir()
        try:
            log.info("Starting post reboot for task")
            self._post_reboot(task)

            log.info("Finished post reboot. Starting reset system state for task")
            self._reset_system_state()

            log.info("Finished reset system state. Starting configure task for task")
            self._configure_task(task)

            log.info("Finished configure task. Starting run pre config script for task")
            self._run_pre_config_script(task)

            log.info("Finished run pre config script.")
            environment.dump_env(environment.PHASE_PRE_TEST, task)

            task_state = TASK_CMPLT_AGENT_BUILD_INSTALL_ERROR
            task_log = ''
            repeat_count = convert.to_number_with_default(task.config.get("repeat_count"), 1)
            for i in range(repeat_count):
                task.current_iteration = i
                # run the test
                log.info("Starting job %s", job)
                task_state, task_log = self._run_test(task, job)

                if 1 <= i + 1 < repeat_count:
                    utils.move_files(task_dir, os.path.join(task_dir, "iteration_%d" % i), skip_re="iteration_.*")

            log.info("Finished all tests.")

            environment.dump_env(environment.PHASE_POST_TEST, task)

            log.info("Starting Run post config script and check sut status for task.")
            try:
                self._run_post_config_script(task)
                reboot_needed = False
            except RebootNeededError:
                reboot_needed = True

            sut_status = self._check_sut_status(task)
            if not sut_status['successful']:
                task_log = str_join('\n', task_log, sut_status.get('error', ''))
                task_state = TASK_CMPLT_AGENT_BUILD_VERIFICATION_FAILED

            log.info("Finished post config script and checked sut status. Starting complete task for task.")
            self._complete_task(task, task_state, task_log)
            log.info("Finished complete task. Starting reset system state for task.")
            self._reset_system_state()
            log.info("Finished reset system state for task.")
            # reboot if hardware went astray
            if self.hw_monitor_enabled and not self.hw_monitor.hw_ok and self.reboot_on_hw_error:
                log.info("Found HW error during task (%s) - Rebooting machine", self.hw_monitor.hw_error)
                self.reboot_flag = TARGET_REBOOT

            if reboot_needed:
                raise RebootNeededError

        except (RebootNeededError, ShutdownNeededError):
            raise
        except:
            log.exception("run test job failed")
            self._run_post_config_script(task)
            error = "some problem occurred during task execution:\n%s" % traceback.format_exc()
            self._complete_task(task, TASK_CMPLT_AGENT_EXCEPTION, error)
            self._reset_system_state()

    def _check_sut_status(self, task):
        if self.is_manual_mode():
            return {"successful": True}  # Temporary workaround, test runner will be able to install driver
        wrapper_file = task.get_sut_job()['wrapper_path']
        wrapper_path = "wrappers.%s" % wrapper_file.replace(".py", "")
        try:
            installer = __import__(wrapper_path, globals(), locals(), ['verify'])
            verify = installer.verify
        except (ImportError, AttributeError):
            return {"successful": True}
        try:
            return verify(task)
        except Exception:
            info = "Exception during sut verifying after test, should not happen."
            log.exception(info)
            return {"successful": False, "error": info}

    def _store_extra_results(self, task, dest_dir):
        pass

    def _store_results(self, task, srv_addr=None):
        while not self.server.is_storing_results_allowed(self.mac_address):
            log.info("storing results on server is not allowed now - sleeping for 60 seconds")
            self.agent_status = AGENT_WAITING_FOR_STORING_RESULTS
            time.sleep(60)

        log.info("collecting crashdumps and other logs to task directory")
        self.agent_status = AGENT_STORING_RESULTS
        self._store_mem_dumps_to_task_dir(task)
        self._store_system_logs_to_task_dir(task)

        dest_dir = self.repo.get_results_dir(task)
        log.info("storing results from %s  to %s with quota: %s MB" % (task.get_dir(), dest_dir, self.logs_quota / 1024.0 ** 2))
        if self.logs_quota:
            self.logs_quota -= utils.copy_agent_logs_with_quota(task.get_dir(), dest_dir, self.logs_quota, srv_addr=srv_addr)
            if self.logs_quota > 0:
                utils.copy_files(task.get_dir(), dest_dir, ignore_errors=True, quota=self.logs_quota, srv_addr=srv_addr)
        else:
            utils.copy_files(task.get_dir(), dest_dir, ignore_errors=True, srv_addr=srv_addr)

        self._store_extra_results(task, dest_dir)

        self.repo.push_results(task)

        while os.path.exists(os.path.join(dest_dir, consts.RESULTS_LOG)) and \
                not self.server.is_results_log_visible_by_server(task.get_id()):
            log.info("results-log.txt is not visible on the server side yet "
                     "while present on agent's share - sleeping for 60 seconds")
            time.sleep(60)

        try:
            utils.rm_tree(task.get_dir())
        except:
            log.exception("Could not remove task dir after storing results.")

    def _complete_task(self, task, state, task_log=None):
        if checks.is_linux():
            # Ensure that all files generated by tool are accessible by Berta
            # +w ensures that agent will be able to write into task directory (i.e.: agent_error.txt).
            cmd = "sudo chmod a+rw -R %s" % task.get_dir()
            out, ret = utils.exec_with_timeout(cmd, 15, shell=True)
            if ret != 0:
                log.error("Cannot change permissions in directory: %s: %s" % (task.get_dir(), out))

        if task_log:
            self.write_task_error(task, task_log)

        # truncate big *.log and *.txt files (>20MB)
        max_size = int(task.config.get('logs_max_size', 20971520))
        for dirpath, _, filenames in os.walk(task.get_dir()):
            for f in filenames:
                if fnmatch.fnmatch(f, '*.txt') or fnmatch.fnmatch(f, '*.log'):
                    ff = os.path.join(dirpath, f)
                    size = os.stat(ff).st_size
                    if size > max_size:
                        with open(ff, 'a+') as big_file:
                            log.debug("%s size: %s truncate file to %d" % (f, size, max_size))
                            big_file.truncate(max_size)

        # copy log files to samba repository
        srv_addr = get_srv_address()
        if self.mode in (self.SERVER_AGENT_MODE, self.SAFE_MODE):
            self._store_results(task, srv_addr=srv_addr['ip'])

        self._note_last_completed_task(task, state)
        # send task results
        log.info("notifing task %d completion, state: %s" % (task.get_id(), state))
        task_log = task_log if PY2 else bytes(task_log, 'ascii')
        self.server.task_completed(self.mac_address, task.get_id(), xmlrpclib.Binary(task_log), state)

    def _note_last_completed_task(self, task, state):
        state_file = os.path.join(self.var_dir, 'state.json')
        try:
            with open(state_file, "w") as fp:
                state = {'last_completed_task': {"id": task.get_id(), "state": state}}
                json.dump(state, fp)
        except Exception:
            log.exception('Could not write last completed task state to %s' % state_file)

    def _process_last_task(self, current_task):
        last_task_file = os.path.join(self.var_dir, "last_task.json")
        if not os.path.exists(last_task_file):
            current_task.dump_json(last_task_file)
            return

        try:
            last_task = utils.Task.load_from_file(last_task_file, check_existence=True)
        except:
            log.exception("Problem with reading last_task.json.")
            current_task.dump_json(last_task_file)
            return

        if current_task.get_id() != last_task.get_id():
            os.remove(last_task_file)
            current_task.dump_json(last_task_file)

        reload_os = any(string_bool(t.config.get("reload_os_on_config_change", "")) for t in [current_task, last_task])

        if reload_os and last_task.config != current_task.config:
            log.info('Config changed. Reload os on config change.')
            self._boot_to_imageloader()

    def run_once(self, upgrade_required):
        self.reboot_flag = TARGET_NO_REBOOT
        if not self.is_manual_mode():
            log.debug("HW config before task execution:")
            self.detect_capabilities()
        else:
            log.info("Manual mode of agent detected. Capabilities detection disabled")
        task = self.task = self.get_task()
        if not task:
            self._prev_task_cleanup()
            return self.reboot_flag, True  # reboot, upgrade allowed
        else:
            # cleanup any previous tasks
            self._prev_task_cleanup(str(task.get_id()))
            utils.ensure_dir(self.repo.get_results_dir(self.task))

        if self.hw_monitor_enabled:
            self.hw_monitor.set_task(task)

        self._process_last_task(task)
        self.reboot_flag = self.process_task(task)

        log.debug("HW config after task execution:")
        self.detect_capabilities()

        return self.reboot_flag, True  # reboot, upgrade allowed

    def _post_reboot(self, task):
        if task:
            self._clean_logs_out_of_task(task)
            self._store_mem_dumps_to_task_dir(task)
            self._store_system_logs_to_task_dir(task)

    def _store_mem_dumps_to_task_dir(self, task):
        try:
            self._copy_mem_dumps(task, self.repo.get_results_dir(task))
        except:
            log.exception("store mem dumps failed")
        self._clean_mem_dumps()

    def _copy_mem_dumps(self, task, task_path):
        pass

    def _clean_mem_dumps(self):
        pass

    def _store_system_logs_to_task_dir(self, task):
        pass

    def _clean_logs_out_of_task(self, task):
        file_list = []
        for path in self.logs_search_paths:
            if os.path.isdir(path):
                all_files = [os.path.join(path, f) for f in os.listdir(path)]
                file_list.extend(all_files)
            else:
                file_list.append(path)

        log.info("clean_logs file_list: %s" % file_list)
        for path in file_list:
            try:
                if not os.path.exists(path):
                    continue
                file_mtime = os.path.getmtime(path)
                file_mtime = datetime.datetime.fromtimestamp(file_mtime)
                log.info("clean_logs_out_of_task: checking file %s, file_ctime %s, task.start_time %s" % (path, file_mtime, task.start_time))
                if file_mtime < task.start_time:
                    if path in ['/var/log/syslog', '/var/log/messages']:
                        utils.truncate_file(path)
                    elif os.path.isfile(path):
                        utils.force_remove_file(path)
                    else:
                        utils.force_remove_dir(path)
            except:
                log.exception("clean_logs_out_of_task: checking file %s" % path)


class AgentLinux(AgentGeneric):
    def __init__(self, controller_addr, dirs, repo, mode=BaseAgent.SERVER_AGENT_MODE, use_hw_monitor=None):
        super(AgentLinux, self).__init__(controller_addr, dirs, repo, mode, use_hw_monitor)
        os.environ["DISPLAY"] = ":0"
        self.userspace_dumps_path = "/opt/dumps"
        self.kernelspace_dumps_path = "/var/crash"
        self.logs_search_paths = [self.userspace_dumps_path, self.kernelspace_dumps_path, "/var/log/syslog", "/var/log/messages"]
        self.collect_dump_script = join(self.utils_dir, "collect_dump.py")

        if os.path.exists("/usr/local/py36-agat/bin/python"):
            self.wrapper_interpreters[".py"] = "/usr/local/custom-py/bin/python"
            self.wrapper_interpreters["agat.py"] = "/usr/local/py36-agat/bin/python"
        elif os.path.exists("/usr/local/custom-py/bin/python"):
            self.wrapper_interpreters[".py"] = "/usr/local/custom-py/bin/python"
        elif os.path.exists("/usr/local/bin/python"):
            self.wrapper_interpreters[".py"] = "/usr/local/bin/python"
        else:
            self.wrapper_interpreters[".py"] = "/usr/bin/python"

    def prepare_machine(self):
        super(AgentLinux, self).prepare_machine()

        try:
            distrib, release = checks.get_distro().split(" ")[:2]
        except:
            distrib = "Ubuntu"
            release = "12.04"

        log.debug("OS distribution detected: %s, release: %s" % (distrib, release))

        # create directories on Linux (/mnt/games)
        if checks.is_linux() and not os.path.exists('/mnt/games'):
            log.debug("Directory /mnt/games doesn't exists")
            cmd = "sudo mkdir -p /mnt/games && sudo chmod -R 777 /mnt/games"
            out, ret = utils.exec_with_timeout(cmd, 15, shell=True)
            if ret != 0:
                log.error("Cannot create directory: /mnt/games: %s", out)

        # Disable the display power management.
        try:
            if distrib == "Ubuntu" and release >= "12.04":
                self._switch_off_pwr_mngmt()
            else:
                self._switch_off_pwr_mngmt_legacy()
        except:
            # Switching off the power management can fail in many non-critical
            # ways. The most trivial is that the GNOME is not installed.
            log.warning("Switching off the power management has failed.")

        # Disable core dumps on Yocto
        if distrib == "Poky" and release == "Yocto":
            log.info("Disabling core dumps")
            self._disable_core_dumps()
            log.info("Core dumps disabled")
        else:
            log.info("Enabling core dumps")
            try:
                self._enable_core_dumps()
                log.info("Core dumps enabled (will be collected in %s)" % self.userspace_dumps_path)
            except:
                log.error("Core dumps will not be avalaible")

    def _get_shebang(self, filepath):
        with open(filepath) as f:
            first_line = f.readline()
            if first_line.startswith("#!"):
                return first_line.strip().replace("#!", "")
        return ''

    def _get_interpreter(self, filepath):
        shebang = self._get_shebang(filepath)
        if shebang:
            return shebang
        return super(AgentLinux, self)._get_interpreter(filepath)

    def _disable_core_dumps(self):
        self._set_core_limit(limit="0")

    def _enable_core_dumps(self):
        try:
            self._create_dumps_dir()
        except:
            log.info("Can't store core dumps in %s. Trying /tmp/dumps path" % self.userspace_dumps_path)
            self.userspace_dumps_path = "/tmp/dumps"
            self._create_dumps_dir()
        dump_pattern = "| %s %s %%p %%t" % (self.collect_dump_script, self.userspace_dumps_path)
        exec_with_timeout("sudo su root -c 'echo \"%s\" > /proc/sys/kernel/core_pattern'" % dump_pattern, timeout=10, shell=True, tracing=True, cwd=os.getcwd())
        # ulimit -c is not enough
        self._set_core_limit()

    def _create_dumps_dir(self):
        if not os.path.exists(self.userspace_dumps_path):
            txt, retcode = exec_with_timeout("sudo mkdir -p %s" % self.userspace_dumps_path, timeout=120, shell=True, cwd=os.getcwd())
            if retcode != 0:
                raise Exception("Can't create directory %s because %s" % (self.userspace_dumps_path, txt))
        exec_with_timeout("sudo chmod -R 755 %s" % self.userspace_dumps_path, timeout=120, shell=True, cwd=os.getcwd())

    def _set_core_limit(self, limit="unlimited"):
        limits_file = "/etc/security/limits.conf"
        out, ret = exec_with_timeout("cat %s | grep core | grep -v ^#" % limits_file, timeout=10, shell=True, tracing=True, cwd=os.getcwd())
        lines = out.splitlines()
        if len(lines) > 1:
            log.error("Error: multiple core limits in %s file. This has to be fixed manually", limits_file)
            return
        if len(lines) == 1:
            if "core" in lines[0] and limit in lines[0]:
                return
            _, ret = exec_with_timeout("sudo su root -c 'sed -i -e \"s/^%s//\" %s'" % (lines[0], limits_file),
                                        timeout=10, shell=True, tracing=True, cwd=os.getcwd())
            if ret != 0:
                log.error("Problem with cleaning %s file. This has to be fixed manually", limits_file)
                return
        exec_with_timeout("sudo su root -c 'echo \"* soft core %s\" >> %s'" % (limit, limits_file),
                            timeout=10, shell=True, tracing=True, cwd=os.getcwd())

    def _check_display_available(self):
        # The method uses glxinfo to check if any screens are available
        # Used as a WA for VLV2 Ubuntu machines instabilities
        if not checks.is_android():
            log.info("Checking display availability")
            cmd = "glxinfo"
            out, ret = exec_with_timeout(cmd, 45, shell=True)
            if ret != 0:
                log.error("Error running glxinfo \n:%s", out)
                raise RebootNeededError()

    def _switch_off_pwr_mngmt(self):
        dconf_dir = "/home/berta/.config/dconf"
        if not os.path.exists(dconf_dir):
            os.mkdir(dconf_dir)
        dconf_keys = [["org.gnome.settings-daemon.plugins.power", "idle-dim-ac", "false"],
                      ["org.gnome.settings-daemon.plugins.power", "idle-dim-battery", "false"],
                      ["org.gnome.settings-daemon.plugins.power", "sleep-display-ac", "0"],
                      ["org.gnome.settings-daemon.plugins.power", " sleep-display-battery", "0"],
                      ["org.gnome.desktop.screensaver", "lock-enabled", "false"],
                      ["org.gnome.desktop.screensaver", "ubuntu-lock-on-suspend", "false"]]
        for path, key, value in dconf_keys:
            cmd = "gsettings set %s %s %s" % (path, key, value)
            out, ret = exec_with_timeout(cmd, 45, shell=True)
            if ret != 0:
                log.error("Cannot switch off gconf key %s.%s", path, key)
                raise FailedStartingXServerError()
            log.info("switching off: %s, out: %s" % (cmd, out))
            # check
            cmd = "gsettings get %s %s " % (path, key)
            out, ret = exec_with_timeout(cmd, 5, shell=True)
            if out.strip() != value:
                log.error("Cannot switch off gconf key %s.%s, read value %s, expected %s", path, key, out, value)
                raise FailedStartingXServerError()
            log.info("checking off: %s, out: %s" % (cmd, out))

    def _switch_off_pwr_mngmt_legacy(self):
        gconf_keys = [["int", "/apps/gnome-screensaver/idle_delay", "0"],
                      ["bool", "/apps/gnome-screensaver/idle_activation_enabled", "false"],
                      ["int", "/apps/gnome-power-manager/timeout/sleep_display_ac", "0"]]
        for key_type, key_name, value in gconf_keys:
            # set
            cmd = "sudo gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --type %s --set %s %s" % (key_type, key_name, value)
            out, ret = exec_with_timeout(cmd, 45, shell=True)
            if ret != 0:
                log.error("Cannot switch off gconf key %s", key_name)
                raise FailedStartingXServerError()
            log.info("switching off: %s, out: %s" % (cmd, out))
            # check
            cmd = "sudo gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get %s" % key_name
            out, ret = exec_with_timeout(cmd, 5, shell=True)
            if out.strip() != value:
                log.error("Cannot switch off gconf key %s, read value %s, expected %s", key_name, out, value)
                raise FailedStartingXServerError()
            log.info("checking off: %s, out: %s" % (cmd, out))

    def _purge_home(self):
        # purge any unnecessary files from $HOME
        log.info("Purging unnecessary files from $HOME")
        white_list = [
            "data",
            ".bash_history",
            ".bash_logout",
            ".bashrc",
            "berta",
            ".ssh",
            "oglc",
            ".config",
            ".gconf",
            ".local",
            ".cache",
            ".compiz",
            ".Xauthority",
            ".ICEauthority",
            ".profile",
            ".gvfs",
            ".vimrc",
            ".byobu",
            ".vnc",
            "run-berta.sh",
            "system_flavour.txt",
            "mnt",
            "python"]
        for f in os.listdir(os.getenv("HOME")):
            if f in white_list or fnmatch.fnmatch(f, "*.xml") or f.startswith('.nfs'):
                continue
            try:
                p = join(os.getenv("HOME"), f)
                log.info("Delete: %s", p)
                if not os.path.isdir(p):
                    utils.force_remove_file(p)
                    continue

                with open("/proc/mounts") as handle:
                    used_as_a_mnt_point = any(line.split()[1].startswith(p) for line in handle)

                if used_as_a_mnt_point:
                    log.warning("Omitting directory because it has mounted filesystem in it.")
                    continue
                utils.rm_tree(p)
            except:
                log.exception("Cannot clean '%s'", p)
                txt, ret = exec_with_timeout("lsof %s " % p, 10, shell=True)
                if ret == 0:
                    log.warning("lsof output: %s" % txt)

    def _reset_system_state(self):
        if self.mode != self.SERVER_AGENT_MODE:
            return

        if self.target.get('clear_home_dir', True):
            self._purge_home()

        # Reset syslog. It is better to use truncate to clear those files.
        utils.truncate_file("/var/log/syslog")
        utils.truncate_file("/var/log/messages")
        os.system("sudo systemctl restart rsyslog.service")
        # delete core dumps
        self._clean_mem_dumps()

    def _configure_task(self, task):
        super(AgentLinux, self)._configure_task(task)

        # At the end, check if the display is available by running glxinfo
        # If not - go for reboot
        if 'skip_glxinfo_check' in task.config and task.config['skip_glxinfo_check'] == 'True':
            log.info("Skipping check display availability")
        elif task.get_sut_job()['product'] == "ufo":
            self._check_display_available()

    def _copy_mem_dumps(self, task, task_path):
        log.info("Searching for core dumps")
        timeout = 30
        sleep_time = 10
        while utils.pidof(os.path.basename(self.collect_dump_script)) and timeout > 0:
            self.agent_status = AGENT_COPYING_MEMDUMPS
            time.sleep(sleep_time)
            timeout -= sleep_time
        task_path_local = task.get_dir()

        dumps_paths = []
        if utils.is_dir_nonempty(self.userspace_dumps_path):
            dumps_paths.append(self.userspace_dumps_path)
        if utils.is_dir_nonempty(self.kernelspace_dumps_path):
            dumps_paths.append(self.kernelspace_dumps_path)

        if dumps_paths:
            log.info("Found core dumps in %s", ','.join(dumps_paths))
            archive_filename = "coredumps_%s_%s.tar.xz" % (task.get_id(), time.strftime("%Y_%m_%d_%H_%M_%S", time.localtime()))
            archive_dest_path = join(task_path_local, "crashdumps")

            if not os.path.exists(archive_dest_path):
                os.makedirs(archive_dest_path)
            dirs_to_archive = ' '.join(dumps_paths)
            exec_with_timeout("sudo chmod -R 755 %s " % dirs_to_archive, timeout=60, shell=True, cwd=os.getcwd())
            cmd = "tar -cJ -f %s %s" % (os.path.join(archive_dest_path, archive_filename), dirs_to_archive)
            ret = exec_with_timeout(cmd, timeout=3 * 600, shell=True, tracing=True, cwd=os.getcwd())[1]
            if ret != 0:
                exec_with_timeout("busybox %s" % cmd, timeout=600, shell=True, tracing=True, cwd=os.getcwd())

    def _clean_mem_dumps(self):
        if self.clean_memory_dump:
            log.info("Cleaning memory dumps")
            exec_with_timeout("sudo pkill -9 -f %s" % self.collect_dump_script, timeout=120, shell=True)
            if os.path.exists(self.userspace_dumps_path):
                exec_with_timeout("sudo chmod -R 755 %s" % self.userspace_dumps_path, timeout=120, shell=True, cwd=os.getcwd())
                exec_with_timeout("sudo rm -rf %s" % self.userspace_dumps_path, timeout=120, shell=True, cwd=os.getcwd())
            self._create_dumps_dir()
        else:
            log.info("Clean memory dump is disabled! Saving...")

    def _store_system_logs_to_task_dir(self, task):
        # Copy system logs to task dir firstly to get better control on its size
        results_dir = task.get_dir()
        timestamp = time.strftime("%Y_%m_%d_%H_%M_%S", time.localtime())
        if os.path.exists("/var/log/messages"):
            messages_dest = os.path.join(results_dir, "messages_%s" % timestamp)
            exec_with_timeout("sudo cp /var/log/messages %s" % messages_dest, timeout=30, shell=True)
            exec_with_timeout("sudo chmod 755 %s" % messages_dest, 30, shell=True)
        if os.path.exists("/var/log/syslog"):
            syslog_dest = os.path.join(results_dir, "syslog_%s" % timestamp)
            exec_with_timeout("sudo cp /var/log/syslog %s" % syslog_dest, timeout=30, shell=True)
            exec_with_timeout("sudo chmod 755 %s" % syslog_dest, 30, shell=True)
        xorglog_dest = os.path.join(results_dir, "Xorg.0.log")
        exec_with_timeout("sudo cp /var/log/Xorg.0.log %s" % xorglog_dest, timeout=30, shell=True)
        exec_with_timeout("sudo chmod 755 %s" % xorglog_dest, 30, shell=True)


class AgentMac(AgentGeneric):
    def __init__(self, controller_addr, dirs, repo, mode=BaseAgent.SERVER_AGENT_MODE, use_hw_monitor=None):
        super(AgentMac, self).__init__(controller_addr, dirs, repo, mode, use_hw_monitor)
        self.wrapper_interpreters[".py"] = "python"

    def prepare_machine(self):
        super(AgentMac, self).prepare_machine()

        # Limit coredumps  to 10 MiB
        self._set_max_coredump_size(10 * (1024 ** 2))

        # Disable the display power management.
        try:
            self._switch_off_pwr_mngmt()
        except:
            log.warning("Switching off the power management has failed.")

    def _check_disk_space(self):
        # minimum required free space (in GB) on disk before starting a task
        system_disk_free_space = SYSTEM_DISK_FREE_SPACE_MAC
        cache_disk_free_space = CACHE_DISK_FREE_SPACE_MAC
        try:
            params = self.task.get_params()
            tmp = params.splitlines()
            for line in tmp:
                if "system_disk_free_space" in line:
                    system_disk_free_space = int(line.split("=")[1].strip())
                if "cache_disk_free_space" in line:
                    cache_disk_free_space = int(line.split("=")[1].strip())
        except:
            log.info("Incorrect values passed in machine params, using default")
            system_disk_free_space = SYSTEM_DISK_FREE_SPACE_MAC
            cache_disk_free_space = CACHE_DISK_FREE_SPACE_MAC

        out, _ = utils.exec_with_timeout("df -m / | grep dev", 10, shell=True)
        free = int(out.split()[3])
        if free < system_disk_free_space * 1024:
            # force OS reload
            log.info("Not enough free space on system disk, forcing OS reload")
            booting.set_boot_to_imageloader()
            raise RebootNeededError("Rebooting machine to imageloader because of not enough free system disk space")

        out, _ = utils.exec_with_timeout("df -m / | grep dev", 10, shell=True)
        free = int(out.split()[3])
        log.info("Free space on system disk: " + str(free) + "M")
        root_device = out.split()[0]

        if os.path.exists("/mnt/cache"):
            out, _ = utils.exec_with_timeout("df -m /mnt/cache | grep dev", 10, shell=True)
            # check if /mnt/cache is on different device than /
            cache_device = out.split()[0]
            if cache_device != root_device:
                # check free disk space on cache disk and delete content if needed
                free = int(out.split()[3])
                log.info("Free space on cache disk: " + str(free) + "M")

                if free < cache_disk_free_space * 1024:
                    log.info("Deleting unnecessary files/folders from cache disk")
                    allowed_dirs = ["berta", "frameworks"]
                    paths = [d for d in os.listdir("/mnt/cache")]
                    deleted = 0
                    for p in paths:
                        if p in allowed_dirs:
                            continue
                        utils.exec_with_timeout("sudo rm -rf /mnt/cache/" + str(p), 60, shell=True)
                        deleted += 1
                    if deleted > 0:
                        out, _ = utils.exec_with_timeout("df -m /mnt/cache | grep dev", 10, shell=True)
                        free = int(out.split()[3])
                        log.info("Free space after deleting: " + str(free) + "M")

    def _set_max_coredump_size(self, size):
        log.info("Limiting maximum core dumps to %d bytes" % size)
        cmd = "sudo launchctl limit core 0 %d" % size
        _, ret = exec_with_timeout(cmd, 5, shell=True)
        if ret != 0:
            log.error("Cannot limit core size to %d" % size)
        else:
            log.info("Core dumps limited to %d" % size)

    def _switch_off_pwr_mngmt(self):
        defaults_keys = [["com.apple.screensaver", "idleTime", "0"]]
        pmset_keys = [["sleep", "0"],
                    ["standby", "0"],
                    ["halfdim", "0"],
                    ["networkoversleep", "0"],
                    ["disksleep", "0"],
                    ["displaysleep", "0"]]

        for path, key, value in defaults_keys:
            cmd = "defaults -currentHost write %s %s %s" % (path, key, value)
            out, ret = exec_with_timeout(cmd, 45, shell=True)
            if ret != 0:
                log.error("Cannot switch off defaults key %s.%s", path, key)
            log.info("switching off: %s, out: %s" % (cmd, out))
            # check
            cmd = "defaults -currentHost read %s %s " % (path, key)
            out, ret = exec_with_timeout(cmd, 5, shell=True)
            if out.strip() != value:
                log.error("Cannot switch off defaults key %s.%s, read value %s, expected %s", path, key, out, value)
            log.info("checking off: %s, out: %s" % (cmd, out))

        for key, value in pmset_keys:
            cmd = "sudo pmset -a %s %s" % (key, value)
            out, ret = exec_with_timeout(cmd, 45, shell=True)
            if ret != 0:
                log.error("Cannot switch off pmset key %s", key)
            log.info("switching off: %s, out: %s" % (cmd, out))
            # check
            cmd = "sudo pmset -g"
            out, ret = exec_with_timeout(cmd, 5, shell=True)
            key_exists = 0
            out_value = ''
            lines = out.split("\n")
            for line in lines:
                #replace tabs to spaces
                line = line.replace("\t", "    ")
                if " " + key + " " in line:
                    key_exists = 1
                    out_value = line.split()[1]
                    break
            if key_exists == 0:
                log.error("key %s does not exists", key)
            elif value != out_value:
                log.error("Cannot switch off defaults key %s, read value %s, expected %s", key, out_value, value)
            log.info("checking off: %s, out: %s" % (key, out_value))

    def _configure_task(self, task):
        # Calling configure from AgentGeneric
        super(AgentMac, self)._configure_task(task)

        # check free disk space
        self._check_disk_space()

        # Invoked before task execution.
        hardware = dmidecode.detect()
        log.info("\t%-30s: %s" % ("active GPU Card", hardware['active_gpu_name']))
        log.info("\t%-30s: %s" % ("number of GPU devices", hardware['number_of_gpu_dev']))

        config_script = ""
        if 'script' in task.config:
            config_script = task.config['script']

        if config_script != "":
            output, ret = utils.exec_with_timeout("nvram -p", 10, shell=True)
            config_before = checks.parse_nvram(output.split('\n'))
            log.info(config_before)
            log.info("Running config script (pre-actions)")
            out, ret = exec_with_timeout(join(self.SHARE_MNT_POINT, 'repository/tools/config/', config_script),
                                        15 * 60, shell=True)
            if ret != 0:
                log.info("Config script returned unexpected return code %d: %s" % (ret, out))
                return False
            output, ret = utils.exec_with_timeout("nvram -p", 10, shell=True)
            config_after = checks.parse_nvram(output.split('\n'))
            log.info(config_after)
            if (config_before['boot-args'] == config_after['boot-args']) and (config_before['GfxMode'] == config_after['GfxMode']):
                return True
            else:
                log.info("rebooting...")
                raise RebootNeededError("Changing configuration")
            log.info("Pre-actions completed.")

    def _copy_mem_dumps(self, task, task_path):
        dumps = crashdumps.copy_mem_dumps(task)
        if dumps:
            log.info("Copying memory dumps - saved dumps: %s" % dumps)
        else:
            log.info("Copying memory dumps - not found dump files.")

    def _clean_mem_dumps(self):
        utils.exec_with_timeout("sudo rm -f /Library/Logs/DiagnosticReports/", timeout=10, shell=True, cwd=os.getcwd())
        utils.exec_with_timeout("sudo rm -f ~/Library/Logs/DiagnosticReports/", timeout=10, shell=True, cwd=os.getcwd())
        log.info("Cleaning crashlogs completed.")


class AgentAndroid(AgentLinux):
    def __init__(self, controller_addr, dirs, repo, mode=BaseAgent.SERVER_AGENT_MODE, use_hw_monitor=None):
        super(AgentLinux, self).__init__(controller_addr, dirs, repo, mode, use_hw_monitor)

    def prepare_machine(self):
        AgentGeneric.prepare_machine(self)

        # TODO Disable the display power management.
        # TODO Check if network is up - bootstrap side
        # ----------------------------------------------------------------------
        # PRESI
        # Wait till Android desktop is loaded, then switch back to HW rendering
        # ----------------------------------------------------------------------
        bootstate = False
        i = 0
        prop = "sys.boot_completed"
        log.info("Waiting for android boot completion...")
        while i < 120:  # 20 minute timeout
            txt, ret = exec_with_timeout("getprop %s " % prop, 10, shell=True)
            if ret != 0:
                log.warning("Cannot read '%s' property: %s" % (prop, txt))
            elif "1" in txt:
                log.info("Android boot completed")
                bootstate = True
                break
            time.sleep(10)
            i += 1

        if re.search("PRE_SI", checks._get_linux_name()):
            log.info("Simulation testing - there is no sys.boot_completed prop.")
            bootstate = True

        if not bootstate:
            log.error("Timeout waiting for android boot completion!")
            if booting.set_boot_to_imageloader():
                log.info("Changed boot entry to image loader OS.")
            else:
                log.error("Failed changing GRUB boot entry to image loader OS.")
            raise RebootNeededError("Android doesn't start correctly, rebooted...")

        # Disable the display power management.
        try:
            self._switch_off_pwr_mngmt()
        except RebootNeededError:
            raise RebootNeededError()
        except:
            # Switching off the power management can fail in many non-critical
            # ways. The most trivial is that the GNOME is not installed.
            log.warning("Switching off the power management has failed.")
        # Disable SELinux - causes Samba write problems on 4.4
        utils.exec_with_timeout("setenforce 0", 10, shell=True)

    def _switch_off_pwr_mngmt(self):
        fields = [["/data/data/com.android.providers.settings/databases/settings.db", "screen_off_timeout", "system", "99999999", False],
                  ["/data/data/com.android.providers.settings/databases/settings.db", "dim_screen", "system", "0", False],
                  ["/data/data/com.android.providers.settings/databases/settings.db", "stay_on_while_plugged_in", "global", "3", False],
                  ["/data/data/com.android.providers.settings/databases/settings.db", "lockscreen.disabled", "secure", "1", False],
                  ["/data/data/com.android.providers.settings/databases/settings.db", "screensaver_enabled", "secure", "0", False],
                  ["/data/data/com.android.providers.settings/databases/settings.db", "screensaver_activate_on_dock", "secure", "0", False],
                  ["/data/data/com.android.providers.settings/databases/settings.db", "package_verifier_enable", "global", "0", False],
                  ["/data/data/com.android.providers.settings/databases/settings.db", "device_provisioned", "global", "1", False],
                  ["/data/data/com.android.providers.settings/databases/settings.db", "user_setup_complete", "secure", "1", False],
                  ["/data/system/locksettings.db", "lockscreen.disabled", "locksettings", "1", False]]

        changed = False

        for database, name, table, value, critical in fields:
            # check if settings is required
            if os.path.exists(database):
                cmd = "sudo sqlite3 %s 'select value from %s where name=\"%s\";' " % (database, table, name)
            else:
                cmd = "sudo settings get %s %s" % (table, name)
            output, ret = exec_with_timeout(cmd, 20, shell=True)
            if output.strip() != value:
                if critical:
                    changed = True
                if os.path.exists(database):
                    cmd = "sudo sqlite3 %s 'update %s set value=\"%s\" where name=\"%s\";'" % (database, table, value, name)
                else:
                    cmd = "sudo settings put %s %s %s" % (table, name, value)
                out, ret = exec_with_timeout(cmd, 20, shell=True)
                if ret != 0:
                    log.error("Cannot set \"%s\" to \"%s\" for table \"%s\" in database \"%s\"", name, value, table, database)
                    if critical:
                        raise FailedStartingXServerError()
                log.info("SET cmd: %s, out: %s" % (cmd, out))
                # check
                if os.path.exists(database):
                    cmd = "sudo sqlite3 %s 'select value from %s where name=\"%s\";' " % (database, table, name)
                else:
                    cmd = "sudo settings get %s %s" % (table, name)
                out, ret = exec_with_timeout(cmd, 20, shell=True)
                if out.strip() != value:
                    log.error("Cannot set \"%s\" for table \"%s\" in database \"%s\", read value \"%s\", expected \"%s\"", name, table, database, out, value)
                    if critical:
                        raise FailedStartingXServerError()
                log.info("CHECK cmd: %s, out: %s" % (cmd, out))
            else:
                log.info("CHECK cmd: %s, out: %s" % (cmd, output))
        if changed == True:
            log.info("Rebooting due to changes in settings database...")
            raise RebootNeededError("Changing configuration")

    def _reset_system_state(self):
        """never, ever remove this function - it overrides linux implementation"""
        if self.mode != self.SERVER_AGENT_MODE:
            return

    def _copy_default_crashdumps(self, crashdump_path, dumps_dir, task_id):
        if os.path.exists(crashdump_path):
            log.info("Trying to copy crashdumps from %s to %s" % (crashdump_path, dumps_dir))
            if len(os.listdir(crashdump_path)) == 0:
                log.info("%s is empty." % crashdump_path)
                return
            try:
                if not os.path.exists(dumps_dir):
                    os.mkdir(dumps_dir)
            except:
                log.info("Can not create folder for crashdumps in %s" % dumps_dir)
            dump_file_name = "tombstones_%s_%s.tar.gz" % (task_id, time.strftime("%Y_%m_%d_%H_%M_%S", time.localtime()))
            ret = utils.exec_with_timeout("tar -c -z -f %s %s" % (dump_file_name, crashdump_path), 500, shell=True)[1]
            if ret != 0:
                ret = utils.exec_with_timeout("busybox tar -c -z -f %s %s" % (dump_file_name, crashdump_path), 500, shell=True)[1]

            try:
                log.info("Trying to move crashdumps from %s to %s" % (dump_file_name, dumps_dir))
                shutil.move(dump_file_name, dumps_dir)
            except Exception as e:
                log.info("Could not copy crashdumps\n%s" % e.message)

            try:
                log.info("Trying to remove crashdumps from %s" % crashdump_path)
                shutil.rmtree(crashdump_path)
            except Exception as e:
                log.info("Could not delete crashdumps\n%s" % e.message)
        else:
            log.info("No crashdumps exist in %s" % (crashdump_path))

    def _copy_mem_dumps(self, task, task_path):
        log.warning('Copying memory dumps not available on Android')

    def _clean_mem_dumps(self):
        log.warning('Cleaning memory dumps not available on Android')

    def _copy_tombstones(self, tombstone_path, crashdump_path):
        if "HSW" in self.target['machines_group_name'] and os.path.exists(tombstone_path):
            log.info("Trying to copy tombstones from %s to %s..." % (tombstone_path, crashdump_path))
            if len(os.listdir(tombstone_path)) == 0:
                log.info("%s is empty." % (tombstone_path))
            else:
                tombstones_dest = os.path.join(crashdump_path, "tombstones")

                try:
                    if not os.path.exists(tombstones_dest):
                        os.makedirs(tombstones_dest)
                    utils.exec_with_timeout("cp %s/* %s" % (tombstone_path, tombstones_dest), 260, shell=True)
                    utils.exec_with_timeout("rm -f %s/*" % (tombstone_path), 260, shell=True)
                except:
                    log.info("Could not copy tombstones from %s to %s" % (tombstone_path, tombstones_dest))

    def _store_extra_results(self, task, dest_dir):
        dumps_dir = join(dest_dir, "crashdumps")
        tombstone_path = "/data/tombstones"
        crashdump_path = "/mnt/sdcard/logs"
        crashdump_path_alternative = "/mnt/logs"

        self._copy_tombstones(tombstone_path, crashdump_path)
        self._copy_default_crashdumps(crashdump_path, dumps_dir, task.get_id())
        self._copy_default_crashdumps(crashdump_path_alternative, dumps_dir, task.get_id())

    def _store_system_logs_to_task_dir(self, task):
        pass


class AgentWindows(AgentGeneric):
    def __init__(self, controller_addr, dirs, repo, mode=BaseAgent.SERVER_AGENT_MODE, use_hw_monitor=None):
        super(AgentWindows, self).__init__(controller_addr, dirs, repo, mode, use_hw_monitor)
        self.HD = utils.get_win_sysdrive_letter()

        if os.path.exists(self.HD + "\\Python36-AGAT\\python.exe"):
            self.wrapper_interpreters['agat.py'] = self.HD + "\\Python36-AGAT\\python.exe"
            self.wrapper_interpreters['.py'] = self.HD + "\\Python27\\python.exe"
        if os.path.exists(self.HD + "\\Python27\\python.exe"):
            self.wrapper_interpreters['.py'] = self.HD + "\\Python27\\python.exe"
        elif os.path.exists(self.HD + "\\Python26\\python.exe"):
            self.wrapper_interpreters['.py'] = self.HD + "\\Python26\\python.exe"
        elif os.path.exists(self.HD + "\\Python25\\python.exe"):
            self.wrapper_interpreters['.py'] = self.HD + "\\Python25\\python.exe"
        else:
            self.wrapper_interpreters['.py'] = "python.exe"

        self.REGISTRY_FILE = join(self.var_dir, "registry.bak")
        logs_locations_list = crashdumps.DUMP_LOCATIONS_WIN
        logs_locations_list.extend(["\\AssertsUMD.txt", "\\AssertsKMD.txt"])
        self.logs_search_paths = [join(self.HD, item) for item in logs_locations_list]
        self.dest_wrappers = "C:\\berta\\wrappers\\"
        self.dest_modules = "C:\\berta\\"

    def _copy_mem_dumps(self, task, task_path):
        self.agent_status = AGENT_COPYING_MEMDUMPS
        file_list = []

        if task is not None and (task.get_sut_job().get("scenario", None) == "DUTPrepareDriverMerge"):
            path_umd_schema = join(self.utils_dir, "UMDQuery.xml")
            path_kmd_schema = join(self.utils_dir, "KMDQuery.xml")
            umd_asserts_path = "%s\\AssertsUMD.txt" % self.HD
            kmd_asserts_path = "%s\\AssertsKMD.txt" % self.HD
            utils.exec_with_timeout("wevtutil qe %s /sq:True /f:XML > %s" % (path_umd_schema, umd_asserts_path), 30, shell=True)
            utils.exec_with_timeout("wevtutil qe %s /sq:True /f:XML > %s" % (path_kmd_schema, kmd_asserts_path), 30, shell=True)
            if os.path.exists(kmd_asserts_path) and os.path.getsize(kmd_asserts_path) != 0:
                file_list.append(kmd_asserts_path)
            if os.path.exists(umd_asserts_path) and os.path.getsize(umd_asserts_path) != 0:
                file_list.append(umd_asserts_path)

        file_list.extend(glob.glob(join(self.HD, "crash_log*")))
        dumps = crashdumps.copy_mem_dumps(task, file_list, self.target_capabilities)
        if dumps:
            log.info("Copying memory dumps - saved dumps: %s" % dumps)
        else:
            log.info("Copying memory dumps - not found dump files.")

    def _reset_system_state(self):
        """ Put any cleaning here. Executed before and after a test. """
        if self.mode != self.SERVER_AGENT_MODE:
            return
        self._clean_mem_dumps()

    def prepare_machine(self):
        super(AgentWindows, self).prepare_machine()

        try:
            import win32api  # pylint: disable=F0401
            win32api.SetConsoleTitle("Berta %s" % self.target['name'])
        except ImportError:
            pass
        log.info("Disable Remote UAC")
        utils.set_reg_value("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "LocalAccountTokenFilterPolicy", 1)

        log.info("Enabling app crashdumps")
        utils.set_reg_value("HKLM", "SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting", "DontShowUI", 1)
        utils.set_reg_value("HKLM", "SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps", "DumpCount", 20)
        utils.set_reg_value("HKLM", "SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps", "DumpType", 2)
        utils.set_reg_value("HKLM", "SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps", "CustomDumpFlags", 0)
        utils.set_reg_value("HKLM", "SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps", "DumpFolder", self.HD + "\\AppCrashDumps")
        utils.set_reg_value("HKLM", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug", "UserDebuggerHotKey", 0)
        utils.set_reg_value("HKLM", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug", "Auto", "0")

        if "AMD64" in platform.machine():
            utils.set_reg_value("HKLM", "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\Windows Error Reporting", "DontShowUI", 1)
            utils.set_reg_value("HKLM", "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps", "DumpCount", 20)
            utils.set_reg_value("HKLM", "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps", "DumpType", 2)
            utils.set_reg_value("HKLM", "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps", "CustomDumpFlags", 0)
            utils.set_reg_value("HKLM", "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps",
                                "DumpFolder", self.HD + "\\AppCrashDumps")
            utils.set_reg_value("HKLM", "SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug", "UserDebuggerHotKey", 0)
            utils.set_reg_value("HKLM", "SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug", "Auto", "0")

        try:
            if booting.get_windows_mode() != "NORMAL":
                booting.set_windows_mode("NORMAL", self.var_dir)
        except ImportError:
            pass
        except Exception:
            log.exception('Ignore exception')

    def _post_install(self):
        """ Invoked after successful build installation. """
        try:
            os.remove(self.REGISTRY_FILE)
            log.debug("Removed registry backup: {file}".format(file=self.REGISTRY_FILE))
        except:
            log.warning("Cannot remove registry backup %s" % self.REGISTRY_FILE)

        super(AgentWindows, self)._post_install()

    def _configure_task(self, task):
        # Calling configure from AgentGeneric
        super(AgentWindows, self)._configure_task(task)

        # Invoked before task execution.
        if not self.target.get('do_registry_bak') or string_bool(task.config.get("skip_registry_backup", '')):
            log.info("Skipping registry backup.")
        else:
            self.agent_status = AGENT_REGISTRY_BACKUP
            utils.registry_backup(self.REGISTRY_FILE)
        config_script = ""
        if 'script' in task.config:
            config_script = task.config['script']

        if config_script != "":
            log.info("Running config script (pre-actions)")
            retcode = exec_with_timeout("cmd /c " + join(self.SHARE_MNT_POINT, 'repository/tools/config', config_script),
                                        15 * 60, shell=True)
            if retcode != 0:
                log.info("Config script returned unexpected return code: " + str(retcode))
                return False
            log.info("Pre-actions completed.")

        return True

    def _store_extra_results(self, task, dest_dir):
        # save potential call stack dumps
        crashes = glob.glob(join(self.var_dir, "crash_*.txt"))
        callstack_dir = join(dest_dir, "callstack")
        if crashes and not os.path.exists(callstack_dir):
            os.makedirs(callstack_dir)
        for f in crashes:
            shutil.copy(f, callstack_dir)

    def _run_post_config_script(self, task):
        super(AgentWindows, self)._run_post_config_script(task)
        utils.registry_restore(self.REGISTRY_FILE)

    def _clean_mem_dumps(self):
        log.info("Cleaning memory dumps")
        if (self.task != None) and (self.task.get_sut_job().get("scenario", None) == "DUTPrepareDriverMerge"):
            utils.exec_with_timeout("wevtutil cl System", 30, shell=True)
            utils.exec_with_timeout("wevtutil cl Application", 30, shell=True)
        exec_with_timeout("cmd /c DEL /F /Q %s\\AssertsUMD.txt" % self.HD, 30, shell=True, cwd=self.HD)
        exec_with_timeout("cmd /c DEL /F /Q %s\\AssertsKMD.txt" % self.HD, 30, shell=True, cwd=self.HD)
        # clear all existing crash dumps
        exec_with_timeout("cmd /c \"CD %SystemRoot%\\Minidump && CD && RMDIR /S /Q .\"", 20, shell=True, cwd=self.HD)
        exec_with_timeout("cmd /c \"CD %SystemRoot%\\LiveKernelReports\\WATCHDOG && RMDIR /S /Q .\"", 10, shell=True, cwd=self.HD)
        exec_with_timeout("cmd /c DEL /F /Q %SystemRoot%\\MEMORY.DMP", 120, shell=True, cwd=self.HD)
        exec_with_timeout("cmd /c \"CD %TMP% && RMDIR /S /Q .\"", 30, shell=True, cwd=self.HD)
        exec_with_timeout("cmd /c \"CD %LOCALAPPDATA%\\CrashDumps && CD && RMDIR /S /Q .\"", 20, shell=True, cwd=self.HD)
        exec_with_timeout("cmd /c \"CD %s\\AppCrashDumps && CD && RMDIR /S /Q .\"" % self.HD, 20, shell=True, cwd=self.HD)
        exec_with_timeout("cmd /c \"CD %SystemRoot%\\MemDumpArc && CD && RMDIR /S /Q .\"", 20, shell=True, cwd=self.HD)
        exec_with_timeout("cmd /c DEL /F /Q %s\\CrashDetails.xml" % self.HD, 30, shell=True, cwd=self.HD)

        crashes = glob.glob(join(self.var_dir, "crash_*.txt"))
        for f in crashes:
            try:
                os.remove(f)
            except:
                log.exception("Could not delete call stack dump file: %s", f)

        testcase_crashlogs = glob.glob(join(self.HD, "crash_log_*"))
        for d in testcase_crashlogs:
            try:
                shutil.rmtree(d)
            except:
                log.exception("Could not delete crashlog directory: %s", d)


class AgentFreeBSD(AgentGeneric):
    def __init__(self, controller_addr, dirs, repo, mode=BaseAgent.SERVER_AGENT_MODE, use_hw_monitor=None):
        super(AgentFreeBSD, self).__init__(controller_addr, dirs, repo, mode, use_hw_monitor)
        if os.path.exists("/usr/local/py36-agat/bin/python"):
            self.wrapper_interpreters["agat.py"] = "/usr/local/py36-agat/bin/python"
        if os.path.exists("/usr/local/custom-py/bin/python"):
            self.wrapper_interpreters[".py"] = "/usr/local/custom-py/bin/python"
        elif os.path.exists("/usr/local/bin/python"):
            self.wrapper_interpreters[".py"] = "/usr/local/bin/python"
        else:
            self.wrapper_interpreters[".py"] = "/usr/bin/python"


class AgentESXi(AgentGeneric):
    def __init__(self, controller_addr, dirs, repo, mode=BaseAgent.SERVER_AGENT_MODE, use_hw_monitor=None):
        super(AgentESXi, self).__init__(controller_addr, dirs, repo, mode, use_hw_monitor)
        if os.path.exists("/scratch/berta/python27"):
            self.wrapper_interpreters[".py"] = "/scratch/berta/python27"


def get_agent_class():
    # machine readable OS string
    global SYSTEM  # pylint: disable=W0603
    SYSTEM = checks.get_system()
    plat = platform.system()

    log.info("Detected platform: %s", plat)
    log.info("Detected system: %s", SYSTEM)

    # initiate and start correct agent
    if checks.is_android():
        agent_class = AgentAndroid
    elif checks.is_linux():
        agent_class = AgentLinux
    elif checks.is_esx():
        agent_class = AgentESXi
    elif checks.is_macos():
        agent_class = AgentMac
    elif checks.is_freebsd():
        agent_class = AgentFreeBSD
    elif checks.is_windows():
        agent_class = AgentWindows
    else:
        log.exception("Cannot recognize platform: %s", plat)
    return agent_class
