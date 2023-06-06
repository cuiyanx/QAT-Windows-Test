""" Common functions used by agent, controller and manager, etc. """

from __future__ import absolute_import, print_function, division

import itertools
import logging
import subprocess
import os
import stat
import time
import re
import socket
import select
import threading
import platform
import tempfile
import zipfile
import datetime
import shutil
import traceback
import sys
import io
import hashlib
import string
import json
import copy
import fnmatch
import binascii

from collections import defaultdict
from contextlib import contextmanager
from functools import partial
from data_utils import filter_names_not_bad_endings
from six import integer_types

if platform.system() == "Windows":
    import ctypes

try:
    import winreg  # pylint: disable=F0401
except ImportError:
    try:
        import _winreg as winreg  # pylint: disable=F0401
    except ImportError:
        pass

import checks
import sshsession
import consts

from py2py3 import make_unicode, string_types, safe_iter_text, safe_bytes2string, ensure_bytes, xmlrpclib, html_parser, RawConfigParser, ConfigParserError, PY2


_LOCAL_DEFAULT = object()

# return code for exec_with_timeout if cmd gets killed
RETCODE_TERMINATED = -50
RETCODE_RUNNING = -51
# Return code for indicating that reboot is needed.
# Needs to be positive for compatibility with Linux agent.
RETCODE_TRIGGER_OFF_REBOOT = 52
RETCODE_SPECIAL_STATUS = 53
# Return codes to indicate need to re-run (schedule again) same task with or without canceling of original.
RETCODE_RE_RUN_TASK = 60
RETCODE_CANCEL_AND_RE_RUN_TASK = 61
# String appended to file when it is truncated.
TRUNCATE_MARK = b"-=QUOTA EXCEEDED: REST OF THE FILE CONTENT TRUNCATED=-"

USE_RSYNC_FOR_COPY = 0

log = logging.getLogger(__name__)


class FailedStartingXServerError(Exception):
    pass


class RebootNeededError(Exception):
    pass


class ShutdownNeededError(Exception):
    pass


class RestartScript(Exception):
    pass


class NetworkError(Exception):
    pass


class SetupNotResponding(Exception):
    pass


class NoConfigAgentRemote(Exception):
    """Raise when can't find config for remote agent"""
    pass


class KilledByCallbackError(Exception):
    pass


class TerminatedDueToTimeoutError(Exception):
    pass


def memorize(fun):
    cached = {}

    def wrapper(*args):
        if args in cached:
            return cached[args]
        else:
            res = fun(*args)
            cached[args] = res
            return res

    return wrapper


def memoize_for_some_time(lifetime):  # in seconds

    def specialized_decorator(func):
        cached = {}

        def outdated(args, now):
            _, when_computed = cached[args]
            return now - when_computed > lifetime

        def wrapper(*args):
            now = time.time()
            if args not in cached or outdated(args, now):
                cached[args] = (func(*args), now)
            res, _ = cached[args]
            return res

        return wrapper

    return specialized_decorator


def join(a, *p):
    if "/" in a:
        good_sep = "/"
        bad_sep = '\\'
    else:
        good_sep = "\\"
        bad_sep = '/'
    part_list = [a.replace(bad_sep, good_sep).rstrip(good_sep)]
    for extra in p:
        extra_parts = extra.replace(bad_sep, good_sep).split(good_sep)
        part_list.extend(extra_parts)
    joined_path = good_sep.join(part for part in part_list if part)
    return joined_path


def rgetattr(target, attr, default=_LOCAL_DEFAULT):
    try:
        for sub_attr in attr.split('.'):
            target = getattr(target, sub_attr)
    except AttributeError:
        if default is not _LOCAL_DEFAULT:
            return default
        raise
    return target


def run_if(predicate, func, *args, **kwargs):
    if predicate:
        return func(*args, **kwargs)


def run_if_dunder_main(value, func, *args, **kwargs):
    return run_if(value == '__main__', func, *args, **kwargs)


def registry_backup(file_name):
    """ First, loads registry from file_name (null op if there is no file_name)
    Then saves registry back to file_name for future load. """
    if os.path.exists(join(os.path.dirname(file_name), 'skip_reg_backup.txt')):
        log.info("Skiping registry backup.")
        return

    log.info("Starting registry backup from %s" % file_name)
    registry_restore(file_name)

    # if not os.path.exists(file_name):
    # store registry backup
    # txt, retcode = exec_with_timeout("regedit /E %s" % file_name, 300, shell=True)
    txt = 0
    retcode = 0
    log.info("Registry storing completed. Returned %d, %s" % (retcode, txt))


def registry_restore(file_name):
    # load clean registry backup (if missing nothing happens)
    # txt, retcode = exec_with_timeout("regedit /S %s" % file_name, 300, shell=True)
    txt = 0
    retcode = 0
    log.info("Registry load returned %d, %s" % (retcode, txt))


def screenshot(filename):
    if checks.is_system("Linux", "Darwin", "FreeBSD"):
        return _screenshot_lx(filename)
    return _screenshot_win(filename)


def _screenshot_lx(_):
    return False


def _screenshot_win(filename):
    """ Screenshots imported from former Berta for Windows """

    try:
        import win32api  # pylint: disable=F0401
        import win32con  # pylint: disable=F0401
        import win32gui  # pylint: disable=F0401
        import win32ui  # pylint: disable=F0401
    except ImportError:
        log.error("Failed importing win32 modules")
        return False

    try:
        # retrieve current system resolution
        width = win32api.GetSystemMetrics(win32con.SM_CXSCREEN)
        height = win32api.GetSystemMetrics(win32con.SM_CYSCREEN)
    except Exception:
        log.error("Failed retrieving system metrics")
        return False

    try:
        # handle of the desktop device context
        tempDC = win32gui.GetWindowDC(win32con.HWND_DESKTOP)
        # handle of DC (as python object)
        hDC = win32ui.CreateDCFromHandle(tempDC)
        # handle of memory DC (as python object)
        memDC = hDC.CreateCompatibleDC()
    except Exception:
        log.error("Failed creating device context")
        return False

    try:
        bitmap = win32ui.CreateBitmap()
        bitmap.CreateCompatibleBitmap(hDC, width, height)

        # select the bitmap with correct size into the DC
        memDC.SelectObject(bitmap)
        # populate memory device context with the data from hDC (screen pixels)
        memDC.BitBlt((0, 0), (width, height), hDC, (0, 0), win32con.SRCCOPY)

        bitmap.SaveBitmapFile(memDC, filename)
    except Exception:
        log.error("Failed creating or saving bitmap")
        return False
    finally:
        memDC.DeleteDC()
        hDC.DeleteDC()
        win32gui.ReleaseDC(win32con.HWND_DESKTOP, tempDC)

    return True


class ExecThread(threading.Thread):
    def __init__(self, cmd, shell, env, cwd, stderr=subprocess.STDOUT, universal_newlines=False, executable=None):
        threading.Thread.__init__(self, name="ExecThread %s" % cmd)
        self.finished = threading.Event()
        self.cmd = cmd
        self.shell = shell
        self.executable = executable
        self.env = env
        self.cwd = cwd
        self.retcode = None
        self.p = None
        self.out_file = None
        self.out_fname = None
        self.stderr = stderr
        self.universal_newlines = universal_newlines

    def run(self):
        out_file_handle = None
        self.out_fname = None
        try:
            try:
                out_file_handle, self.out_fname = tempfile.mkstemp(".txt", "exec_")
            except OSError:
                tempfile.tempdir = None
                out_file_handle, self.out_fname = tempfile.mkstemp(".txt", "exec_")

            proc = dict(args=self.cmd,
                        stdout=out_file_handle,
                        stderr=self.stderr,
                        shell=self.shell,
                        env=self.env,
                        cwd=self.cwd,
                        universal_newlines=self.universal_newlines,
                        executable=self.executable)

            if checks.is_linux():
                # we run setsid before starting the process, so that all children
                # inherit the session id and we can signal them together
                proc['preexec_fn'] = os.setsid

            self.p = subprocess.Popen(**proc)
            if self.p is None:
                log.info('Popen method returned None!')

            self.out_file = open(self.out_fname, "rb")
            self.retcode = self.p.wait()

        except:
            if self.p is None:
                self.p = 1

            log.exception("ExecTread crashed")

        finally:
            if out_file_handle:
                os.close(out_file_handle)
        self.finished.set()


def read_timeout(et, timeout):
    """ Read output from execution thread and return before block """
    text = ""

    if checks.is_linux():
        import fcntl

        try:
            flags = fcntl.fcntl(et.out_file, fcntl.F_GETFL)
            fcntl.fcntl(et.out_file, fcntl.F_SETFL, flags | os.O_NONBLOCK)

            if select.select([et.out_file], [], [], timeout)[0]:
                text = et.out_file.read()
            fcntl.fcntl(et.out_file, fcntl.F_SETFL, flags)
        except ValueError as e:
            if str(e) != "I/O operation on closed file":
                log.exception("problem during select")
                raise
    else:
        import msvcrt  # pylint: disable=F0401
        import win32pipe  # pylint: disable=F0401
        import win32file  # pylint: disable=F0401
        import win32event  # pylint: disable=F0401

        fh = msvcrt.get_osfhandle(et.out_file.fileno())
        ph = et.p._handle  # pylint: disable=W0212
        win32event.WaitForMultipleObjects([fh, ph], False, timeout * 1000)

        try:
            _, n_avail, _ = win32pipe.PeekNamedPipe(fh, 0)
        except Exception as e:
            if e[2] == 'The pipe has been ended.':
                log.info("read_timeout: The pipe has been ended.")
            else:
                log.exception("IGNORED EXCEPTION")
            return text
        if n_avail > 0:
            size = min(n_avail, 10 * 1024)
            _, text = win32file.ReadFile(fh, size, None)

    return text


def device_reboot():
    log.info("Rebooting")
    try:
        system_name, ip = get_remote_agent_conf()
        log.info("Remote %s rebooting: %s" % (system_name, ip))
        if system_name == 'ESXi':
            reboot_remote_esxi(ip)

    except NoConfigAgentRemote:
        if checks.is_system("Linux", "Darwin", "FreeBSD"):
            reboot_lx()
        elif checks.is_esx():
            reboot_esx()
        else:
            reboot_win()

    time.sleep(2)
    raise Exception("still alive ???")


def _privilege_win(priv, enable):
    import win32security  # pylint: disable=F0401
    import win32api  # pylint: disable=F0401
    import ntsecuritycon  # pylint: disable=F0401
    htoken = win32security.OpenProcessToken(win32api.GetCurrentProcess(),
                                            ntsecuritycon.TOKEN_ADJUST_PRIVILEGES | ntsecuritycon.TOKEN_QUERY)

    id_priv = win32security.LookupPrivilegeValue(None, priv)

    win32security.AdjustTokenPrivileges(htoken, 0, [(id_priv, enable)])


def reboot_esx():
    reboot_cmd = "reboot"

    for i in range(2):
        log.info("Rebooting machine, try %s", i)
        _, result = exec_with_timeout(reboot_cmd, 30, shell=True)
        if result != 0:
            time.sleep(2)
            # try again
            exec_with_timeout(reboot_cmd, 60, shell=True)

        log.info("Waiting 8 minutes for shutdown vms and system.")
        time.sleep(480)

        reboot_cmd = "reboot -f"
        log.info("Machine is still alive, %s", reboot_cmd)

        _, result = exec_with_timeout('sync', 16, shell=True)
        if result != 0:
            time.sleep(2)
            # Try again.
            exec_with_timeout('sync', 60, shell=True)


def reboot_remote_esxi(ip):
    """Reboot ESXi machine using remote controller.

    :param ip: IP address for ESXi system
    """
    for i in range(2):
        log.info("Rebooting machine, try %s", i)

        out, rc = exec_local_remote(ip, "root", "sync")
        log.debug("%s: output: %s rc: %s" % ("sync", out, rc))
        if rc != 0:
            raise RuntimeError("Can't write all buffered blocks to disk")

        out, rc = exec_local_remote(ip, "root", "reboot")
        log.debug("%s: output: %s rc: %s" % ("reboot", out, rc))
        if rc != 0:
            raise RuntimeError("Can't remote reboot machine")

        log.info("Waiting 3 minutes for shutdown vms and system.")
        time.sleep(180)


def reboot_win(reboot=1):
    try:
        import win32api  # pylint: disable=F0401
        import ntsecuritycon  # pylint: disable=F0401
    except ImportError:
        win32api = None
    if win32api:
        _privilege_win(ntsecuritycon.SE_SHUTDOWN_NAME,
                       ntsecuritycon.SE_PRIVILEGE_ENABLED)

        while True:
            try:
                win32api.InitiateSystemShutdown(None, "Rebooting...", 0, 1, reboot)
            finally:
                log.info("rebooting machine")
                _privilege_win(ntsecuritycon.SE_SHUTDOWN_NAME, 0)
            time.sleep(0.5)
    else:
        exec_with_timeout("shutdown /r /t 5", timeout=10, shell=True)


def reboot_lx(reboot=1):
    time.sleep(1)
    if reboot:
        if checks.is_android():
            reboot_cmd = "sudo reboot"
        elif checks.is_system("Darwin", "FreeBSD"):
            reboot_cmd = "sudo reboot -q"
        else:
            reboot_cmd = "sudo reboot -f"
    else:
        reboot_cmd = "sudo poweroff"

    # Flush the hard drive cache by calling the 'sync' util.
    # Without it, some recent file I/O operations can be forgotten.
    _, result = exec_with_timeout('sudo sync', 16, shell=True)
    if result != 0:
        time.sleep(2)
        # Try again.
        exec_with_timeout('sudo sync', 60, shell=True)

    time.sleep(5)
    log.info("Rebooting device")
    _, result = exec_with_timeout(reboot_cmd, 16, shell=True)
    if result != 0:
        time.sleep(2)
        # try again
        exec_with_timeout(reboot_cmd, 60, shell=True)


def proc_dump(et):
    if not checks.is_windows():
        return
    if "procdump.exe" in et.cmd:
        # avoid circular dumps
        return
    if not et.shell:  # avoid to dump cmd.exe
        _proc_dump(et.p.pid)
    for pid in get_children_processes(et.p.pid):
        _proc_dump(pid)


def _proc_dump(pid):
    from samba import get_mount_point
    mnt_point = get_mount_point(join(os.environ.get("BERTA_VAR_DIR"), "mnt_point.txt"))
    procdump_path = join(mnt_point, 'repository', 'tools', "procdump", 'procdump.exe')
    if not os.path.exists(procdump_path):
        log.debug("File %s not exists. Skip dump process.", procdump_path)
        return

    dump_dir = join(get_win_sysdrive_letter(), "AppCrashDumps")
    try:
        if not os.path.exists(dump_dir):
            os.makedirs(dump_dir)
    except Exception:
        log.exception("Could not create %s", dump_dir)

    dump_path_pattern = join(dump_dir, "HANG.PROCESSNAME_YYMMDD_HHMMSS.dmp")
    cmd = "{procdump_path} -accepteula {pid} {dump_path_pattern}".format(procdump_path=procdump_path,
                                                                         pid=pid,
                                                                         dump_path_pattern=dump_path_pattern)
    txt, rc = exec_with_timeout(cmd, timeout=600)
    if not rc:
        return
    log.error('cmd %s exit with rc %s, output: %s', cmd, rc, txt)


def kill_process(et, brute_force=False):
    try:
        proc_dump(et)

    except Exception:
        log.exception('Could not dump process %s.', et.p.pid)

    if brute_force:
        # Kill process forcefully
        tries = itertools.repeat(2, times=3)
    else:
        # Try to kill process. First attempt is soft. Second uses force switch. Third uses sudo.
        tries = range(3)

    for i in tries:
        if et.retcode is not None:
            # if this is second entrance it means that we killed the process, so set our retcode
            if i > 0:
                et.retcode = RETCODE_TERMINATED
            break

        # set appropriate switch for attempt #
        sudo = ""
        is_linux_darwin_freebsd = checks.is_system("Linux", "Darwin", "FreeBSD")
        if is_linux_darwin_freebsd:
            force = "TERM"
        else:
            force = ""

        if i >= 1:
            if is_linux_darwin_freebsd:
                force = "KILL"
            else:
                force = "/F"

        if i >= 2:
            if is_linux_darwin_freebsd:
                if checks.is_android():
                    sudo = "su 0 "
                else:
                    sudo = "sudo "

        try:
            if checks.is_linux():
                # send signal to session id process group
                if checks.is_android() or checks.is_yocto():
                    cmd_tmpl = '%sbusybox kill -%s %d || %s"busybox kill -%s %d" || %skill -%s %d'
                    cmd = cmd_tmpl % ((sudo, force, os.getpgid(et.p.pid)) * 3)

                else:
                    cmd_tmpl = "%spkill -%s -g %d"
                    cmd = cmd_tmpl % (sudo, force, os.getpgid(et.p.pid))

                kwargs = dict(preexec_fn=os.setsid, shell=True, stderr=subprocess.STDOUT)

            elif checks.is_system("Darwin", "FreeBSD"):
                cmd_tmpl = "%skill -%s %d"
                cmd = cmd_tmpl % (sudo, force, et.p.pid)
                kwargs = dict(preexec_fn=os.setsid, shell=True)

            else:
                cmd = "taskkill.exe /PID %d /T %s" % (et.p.pid, force)
                kwargs = dict(shell=True)

            log.info("kill with cmd: %s", cmd)
            p = subprocess.Popen(cmd, **kwargs)
            p.communicate()  # wait until process ends

        except OSError:
            log.exception("Exception: Could not send SIGTERM to pid %d in loop %d", et.p.pid, i)
            raise

        # wait 5 seconds for child to terminate
        if i == 0:
            attempts = 5

        elif i == 1:
            attempts = 10

        else:
            attempts = 60

        for j in range(attempts):
            log.info("Wait for terminating %d %d", et.p.pid, j)
            if et.retcode is not None:
                break

            time.sleep(1)

    if et.retcode is None and checks.is_linux():
        # We didn't kill the process... rebooting as this is unusual and might affect next test cases
        log.exception("Exception - could not kill the process, rebooting")
        device_reboot()

    time.sleep(2)  # child processes tend to die a little bit later than parent so wait for them 2 secs


def terminate_process(pid, sig=9):
    try:
        pids = get_children_processes(pid)
    except:
        pids = []
        log.error("Could not get children processes for parent %s", pid)

    my_pid = os.getpid()
    for p in pids:
        if p != my_pid:
            kill_process_by_pid(p, sig)
    # kill parent process
    kill_process_by_pid(pid)


def kill_process_by_pid(pid, sig=15):
    try:
        log.info("terminate_process - child process %d" % pid)
        if checks.is_windows():
            PROCESS_TERMINATE = 1
            handle = ctypes.windll.kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
            ctypes.windll.kernel32.TerminateProcess(handle, -1)
            ctypes.windll.kernel32.CloseHandle(handle)
        else:
            os.kill(pid, sig)
            os.waitpid(pid, 0)
        log.info("terminate_process - child process %d - terminated" % pid)
    except IOError:
        pass
    except Exception as e:
        if 'No child process' in str(e):
            pass
        else:
            log.exception("Could not kill process %d", pid)


def kill_processes_by_name(process_name):
    """ Kill all instances of the program specified by name

    :param process_name: program name
    :type process_name: str
    """
    if checks.is_windows():
        command = "taskkill /f /t /im %s.exe" % process_name
    else:
        command = "sudo killall %s" % process_name
    return exec_with_timeout(command, timeout=5, shell=True)


def log_children_processes(ppid):
    if not checks.is_windows():
        return
    try:
        import win32com.client  # pylint: disable=F0401
        wmi = win32com.client.GetObject('winmgmts:')
        children = wmi.ExecQuery('Select * from win32_process where ParentProcessId=%s' % ppid)
        for child in children:
            log.debug("Children process of %s: pid: %s name: %s.", ppid, child.Properties_('ProcessId'), child.Properties_('Caption'))
            if int(ppid) != child.Properties_('ProcessId'):
                log_children_processes(child.Properties_('ProcessId'))
    except Exception:
        log.exception('Could not log children processes of %s', ppid)


def get_children_processes(pid):
    """Get children pids of process 'pid'.

        returns: list of integers
    """

    if checks.is_windows():
        return get_children_processes_win(pid)
    else:
        return get_children_processes_lx(pid)


def get_children_processes_win(ppid):
    import win32com.client  # pylint: disable=F0401
    wmi = win32com.client.GetObject('winmgmts:')
    pids = []
    children = wmi.ExecQuery('Select * from win32_process where ParentProcessId=%s' % ppid)
    for child in children:
        if "conhost.exe" not in str(child.Properties_('Caption')):
            pids.append(int(child.Properties_('ProcessId')))
    if int(ppid) in pids:
        pids.remove(int(ppid))
    return pids


def get_children_processes_lx(pid):
    all_pids = [int(x) for x in os.listdir('/proc') if x.isdigit()]
    children = defaultdict(list)
    for p in all_pids:
        try:
            for line in fread_by_line("/proc/%s/status" % p):
                if line.startswith("PPid:"):
                    parent = int(line.split()[1])
                    children[parent].append(p)
                    break
        except IOError:
            pass
    if pid not in children:
        return []
    pid_children = []
    p_pids = [pid]
    for p in p_pids:
        for child in children[p]:
            pid_children.append(int(child))
            if child not in p_pids and child in children:
                p_pids.append(child)
    return pid_children


def get_pid_list():
    """Get list of currently running process IDs.

        returns: list of integers
    """
    if checks.is_windows():
        return get_pid_list_win()
    else:
        return get_pid_list_lx()


def get_pid_list_win():
    import win32com.client  # pylint: disable=F0401
    pids = []
    wmi = win32com.client.GetObject('winmgmts:')
    children = wmi.ExecQuery('Select ProcessId from win32_process')
    for child in children:
        pids.append(int(child.Properties_('ProcessId')))
    return pids


def get_pid_list_lx():
    return [int(x) for x in os.listdir('/proc') if x.isdigit()]


def get_size(fname):
    with open(fname, "rb") as f:
        f.seek(0, 2)
        return f.tell()


def get_registry_value(key_name, value_name):
    # obsolete
    log.warning("Please replace this function: get_registry_value(key_name, value_name) with: get_reg_value(\"HKEY_CURRENT_USER\", key_name, value_name)!!!")
    log.warning("It is ambiguous, it reads only from HKCU.")
    return get_reg_value("HKEY_CURRENT_USER", key_name, value_name)


def get_reg_value(hive, key_name, value_name, sam=None):
    """
        hive should be string representation of one of registry hives.
        key_name: key name without hive
        value_name: name of value from particular hive and key
        sam: do not use it unless it is required as described below.
        1)
        sam = KEY_READ | KEY_WOW64_32KEY
        for access a 32-bit key from either a 32-bit or 64-bit application.
        2)
        sam = KEY_READ | KEY_WOW64_64KEY
        for access a 64-bit key from either a 32-bit or 64-bit application.
        return: tuple (value, type)
    """
    if sam is None:
        sam = winreg.KEY_READ
    opened_key = _get_hive(hive)
    try:
        aReg = winreg.ConnectRegistry(None, opened_key)
        with winreg.OpenKey(aReg, key_name, 0, sam) as aKey:
            value, val_type = winreg.QueryValueEx(aKey, value_name)
    except:
        # create empty value to indicate problem with reading registry.
        err_str = "Cannot read from {hive}\\{key}\\{value} with attributes {sam}"
        log.warning(err_str.format(hive=hive, key=key_name, value=value_name, sam=sam))
        value = ""
        val_type = winreg.REG_NONE
    return value, val_type


def get_reg_value32(hive, key_name, value_name):
    """ Use for access for 32 bit registry. """
    return get_reg_value(hive, key_name, value_name, sam=winreg.KEY_READ | winreg.KEY_WOW64_32KEY)


def get_reg_value64(hive, key_name, value_name):
    """ Use for access for 64 bit registry. """
    return get_reg_value(hive, key_name, value_name, sam=winreg.KEY_READ | winreg.KEY_WOW64_64KEY)


def _get_hive(hive):
    opened_key = None
    if hive.upper() in ["HKCR", "HKEY_CLASSES_ROOT"]:
        opened_key = winreg.HKEY_CLASSES_ROOT
    elif hive.upper() in ["HKCU", "HKEY_CURRENT_USER"]:
        opened_key = winreg.HKEY_CURRENT_USER
    elif hive.upper() in ["HKLM", "HKEY_LOCAL_MACHINE"]:
        opened_key = winreg.HKEY_LOCAL_MACHINE
    elif hive.upper() in ["HKU", "HKEY_USERS"]:
        opened_key = winreg.HKEY_USERS
    elif hive.upper() in ["HKCC", "HKEY_CURRENT_CONFIG"]:
        opened_key = winreg.HKEY_CURRENT_CONFIG
    if opened_key is None:
        raise Exception("Unknown windows registry hive name %s", hive)
    return opened_key


def set_reg_value(hive, key, value, data):
    """ Sets windows registry value """
    log.info("Setting registry value %s\\%s\\%s to %s", hive, key, value, data)

    # get proper root key base of hive name
    opened_key = _get_hive(hive)

    # select a good type for data
    if type(data) == int:  # pylint: disable=unidiomatic-typecheck
        data_type = winreg.REG_DWORD
        data = complement(data)
    elif isinstance(data, (str, str)):
        data_type = winreg.REG_SZ
    elif isinstance(data, (list, tuple)):
        data_type = winreg.REG_MULTI_SZ
        data = "\0".join(data)
    elif isinstance(data, bytearray):
        data_type = winreg.REG_BINARY
    else:
        data_type = winreg.REG_NONE

    with winreg.CreateKey(opened_key, key) as aKey:
        winreg.SetValueEx(aKey, value, 0, data_type, data)


def _kill_file_handle(filename):
    set_reg_value("HKCU", "Software\\Sysinternals\\Handle", "EulaAccepted", 1)
    tool = "handle.exe"
    if platform.architecture()[0] == '64bit':
        tool = "handle64.exe"

    pid = pid_line = None
    t, r = exec_with_timeout('{0}/berta/utils/{1}'.format(os.environ['SYSTEMDRIVE'], tool), 120, shell=True)
    look_for = filename.split(os.sep)[-1]
    log.debug("Looking for %s in handle.exe output." % look_for)
    for line in t.splitlines():
        if "pid:" in line:
            m = re.search(".* pid: (\d*) ", line)
            pid = m.group(1)
            pid_line = line

        if look_for in line:
            m = re.search("([A-Fa-f0-9]+): File.*", line)
            handle = m.group(1)
            log.warning(line)
            break

    else:
        # no break -> not found
        log.info("No file handles open for %s" % look_for)
        return

    # more traces
    exec_with_timeout('tasklist | findstr "%s"' % pid, 20, shell=True)

    # traces end here
    log.info("Process hanged on %s file is %s", look_for, pid_line)
    log.info("Detaching file handle %s for PID %s", handle, pid)
    t, r = exec_with_timeout('{0}/berta/utils/{1} -c {2} -y -p {3}'.format(os.environ['SYSTEMDRIVE'], tool, handle, pid), 60, shell=True)
    log.info("handle.exe returned: %s, %s", r, t)


def _try_unlink(filename, timeout=10):
    unlinked = False
    time_step = 0.01
    counter = 0
    time_started = time.time()
    while not unlinked:
        try:
            os.unlink(filename)
            unlinked = True

        except:
            counter = time.time() - time_started
            if counter > timeout:
                raise

            time.sleep(time_step)

    if counter != 0:
        log.info("File %s unlinked after %.2f seconds.", filename, counter)

    return unlinked


def safe_bytes_to_text(bytes_, try_codecs=None):
    try_codecs = try_codecs if try_codecs else ['ascii', 'utf-8', 'utf-16']
    return safe_bytes2string(bytes_, try_codecs).replace('\r\n', '\n')


def exec_with_timeout(cmd, timeout, shell=False, env=None, cwd=None,
                      poll_period=5, callback=None, tracing=False,
                      read_in_chunks=True, screenshot_file=None,
                      force_kill=False, private=False, raise_on_error=False,
                      universal_newlines=False, executable=None, local_log=log):
    """
    Execute a command and kill it if it doesn't finish in "timeout" seconds.
    shell denotes if the cmd is to be interpreted. cwd is current working
    directory, callback is a function to be optionally called every
    poll_period seconds (default 5 seconds) e.g. by the Agent
    """
    if cwd:
        local_cwd = cwd

    else:
        local_cwd = os.getcwd()
        if cwd == "":
            cwd = None

    stderr = subprocess.STDOUT
    if checks.is_android():
        flavour_name = checks.get_flavour_name_lx()
        if "MCG" in flavour_name or checks.is_android_fake():
            if cmd.startswith("sudo"):
                cmd = "su 0 " + cmd[4:].lstrip()
        elif cmd.startswith("sudo"):
            cmd = cmd[4:].lstrip()

    if isinstance(cmd, string_types):
        cmd_txt = cmd
    else:
        cmd_txt = " ".join(cmd)

    if private:
        s = 8
        if cmd_txt.startswith('sudo'):
            s += 5

        cmd_txt = cmd_txt[:s] + '...'

    local_log.debug("starting cmd: %s in %s directory", cmd_txt, local_cwd)
    et = ExecThread(cmd, shell, env, cwd, stderr, universal_newlines, executable)
    et.start()

    # wait for process start
    while not et.p and not et.finished.is_set():
        time.sleep(0.01)

    completed = et.finished.is_set()
    t_start = t_trace = t_cb = t = time.time()
    t_end = t + timeout
    cb_count = 0  # callback iteration counter
    txt = []
    out_size = 0
    while t < t_end and not completed:
        # read output from stdout of started process if needed
        if read_in_chunks and et.out_file:
            part = ""
            s = get_size(et.out_fname)
            ds = s - out_size
            out_size = s
            if ds > 0:
                part = et.out_file.read(ds)
            txt.append(part)
            if tracing and len(part) > 0:
                o = safe_bytes_to_text(part)
                local_log.info("output: " + o)

        t = time.time()
        dt = t - t_trace
        if dt > 60:  # one trace for minute
            t_trace = t
            local_log.info("%s: %.2fsecs to terminate", cmd_txt, t_end - t)

        # call callback if needed
        dt = t - t_cb
        if callback and dt > poll_period:
            t_cb = t
            cb_count += 1
            txt_iter = safe_iter_text(txt)  # input for callback has to to be backward compatible
            txt = ["".join(txt_iter)]
            if not callback(cb_count, poll_period, txt[0], RETCODE_RUNNING):
                local_log.info("callback requested killing command %s", cmd_txt)
                kill_process(et, brute_force=force_kill)

        # check if process completed
        et.finished.wait(poll_period / 4)
        completed = et.finished.is_set()

    # if timeout occurred or process is still running then kill it and et.p != 1 ie. it did not crash during starting
    if (t > t_end or not completed or et.retcode is None) and et.p != 1:
        if t > t_end:
            local_log.warning("command '%s' timed out, timeout: %d secs, start: %s, end: %s",
                              cmd_txt, timeout, t_start, t_end)

        elif not completed:
            local_log.warning("command '%s' not completed", cmd_txt)

        elif et.retcode is None:
            local_log.warning("command '%s' retcode is None", cmd_txt)

        if screenshot_file:
            local_log.info("Taking screenshot")
            if screenshot(screenshot_file):
                local_log.info("Screenshot taken successfully.")

        local_log.warning("Killing the command")
        log_children_processes(et.p.pid)
        kill_process(et, brute_force=force_kill)

    # read the rest from stdout (if it was opened)
    if et.out_file is not None:
        part = et.out_file.read()
        if read_in_chunks:
            txt.append(part)
            if tracing and len(part) > 0:
                local_log.info("output:\n%s", safe_bytes_to_text(part))
        else:
            # or read whole stdout
            txt = [part]
            if tracing:
                local_log.info("output:\n%s", safe_bytes_to_text(txt[0]))

        et.out_file.close()

    unlink_tries = 0
    while unlink_tries < 5:
        try:
            os.unlink(et.out_fname)
        except:
            local_log.exception("Deleting output file %s failed. Closing file handle. (%s# try)", et.out_fname, unlink_tries)
            try:
                _kill_file_handle(et.out_fname)
            except:
                local_log.info("Killing file handle has failed")

        if not os.path.exists(et.out_fname):
            break

        unlink_tries += 1

    if os.path.exists(et.out_fname):
        local_log.warning("File path still exists: %s", et.out_fname)

    txt_iter = safe_iter_text(txt)  # output from function has to to be backward compatible
    out = "".join(txt_iter)
    if callback:
        cb_count += 1
        callback(cb_count, poll_period, out, et.retcode)

    if raise_on_error and et.retcode != 0:
        raise Exception("Failed executing %s, error: %d, msg: %s" % (cmd_txt, et.retcode, out))

    return out, et.retcode


def execute_diskpart(cmd_list):
    """Execute diskpart commands

    :param cmd_list: list of commands that should be executed in diskpart
    :return: output from execution
    """
    diskp_script_file = join(os.environ["BERTA_TMP_DIR"], "diskp_script.txt")
    fwritelines(diskp_script_file, cmd_list)
    cmd = 'diskpart /s %s' % diskp_script_file
    output, rc = exec_with_timeout(cmd, 30, shell=True)
    if rc != 0:
        raise RuntimeError("Error during %s execution: %s" % (cmd, output))
    return output


class XMonitor(threading.Thread):
    """
    This class handles starting, stopping and monitoring the X server.

    Usage:
    Create an object and start it's monitoring thread by:
    xm = utils.XMonitor()
    xm.start()

    Use methods startx() and killx() to start and stop X server.
    Call shutdown() method to stop the monitoring thread.
    Creating XMonitor will shut down the X server if it is already running.

    startx() and killx() are blocking for 60 seconds. FailedStartingXServerError
    exception is raised if X server doesn't start after that time.
    RebootNeededError exception is raised if the X server was started but there is
    no /usr/bin/X11/X is `ps aux`.

    If you want non-blocking X start or stop change the value of self.wanted_state.
    """

    def __init__(self):
        threading.Thread.__init__(self, name="XMonitor")
        # x_running is updated by _check_x_status every 10 sec
        self.x_running = False
        # wanted_state is changed by startx() and killx()
        self.wanted_state = False
        # if XMonitor starts X server, x_process has a Popen object
        self.x_process = None
        # continue_monitoring set to False stops monitoring thread
        self.continue_monitoring = True
        # we don't know what we start with (X running or not). Ready flag is set
        # to true after first cycle of checking X state.
        self.ready = False
        self.start()

    def run(self):
        """ Monitoring thread loop. """
        while self.continue_monitoring:
            self._check_x_status()
            # we want X, but they don't run
            if self.wanted_state and not self.x_running:
                if not self.x_process:
                    # launch X if we want them, but they are not running
                    self._startx()
                else:
                    # raise exception if we have started x (x_process != None)
                    # but check_x_status says there is no X process
                    log.warning("XMonitor: Unexpected X server shutdown.")
                    raise RebootNeededError()

            # kill X if we don't want them and they are running
            elif not self.wanted_state and self.x_running:
                self._killx()

            self.ready = True
            time.sleep(10)

    def _check_x_status(self):
        out, _ = exec_with_timeout("ps aux | grep /usr/bin/X11/X | grep -v grep", 5, shell=True)
        self.x_running = "/usr/bin/X11/X" in out

    def shutdown(self):
        """Stops monitoring thread. """
        self.killx()
        self.continue_monitoring = False

    def _startx(self):
        # Exit if there is already X process
        if self.x_process:
            log.debug("XMonitor: Want to start X, but X process already exists.")
            return

        log.info("Starting X server")
        self.x_process = subprocess.Popen("startx", shell=True)
        time.sleep(10)
        if self.x_process.poll() is not None:
            # txt = "XMonitor: Failed starting X server %s" % self.x_process.poll()
            # log_task_error(task, txt)
            log.warning("XMonitor: Failed starting X server %s", self.x_process.poll())
            raise FailedStartingXServerError()

        log.info("Waiting for X server")
        time.sleep(15)

    def _killx(self):
        """Kills X server without checking if it was stared by XMonitor
        or somebody else."""

        txt, _ = exec_with_timeout("pidof X", 5, shell=True)
        if txt:
            x_pid = int(txt)
            log.info("X server, pid: %d, killing it" % x_pid)
            try:
                os.kill(x_pid, 15)
                time.sleep(5)
                os.kill(x_pid, 9)
            except:
                pass
        else:
            log.info("No X Server to kill, continue")
        self.x_process = None

    def _is_ready(self, timeout):
        """ Blocks if monitoring thread is not ready after start. Raises
        FailedStartingXServerError if the thread isn't ready after /timeout/."""

        # timeout = 60 # seconds
        while not self.ready:
            if timeout < 0 or not self.continue_monitoring:
                break
            time.sleep(1)
            timeout -= 1

        if not self.ready:
            # log.debug("Waiting error! XMonitor")
            log.debug("self wanted state %s", self.wanted_state)
            raise FailedStartingXServerError()

    def _is_switched(self, timeout):
        """
        Blocks until X server is started or stopped as planned.
        Raises FailedStartingXServerError if the thread isn't ready after
        /timeout/.
        """

        # timeout = 60 # seconds
        while self.wanted_state != self.x_running:
            if timeout < 0 or not self.continue_monitoring:
                break
            time.sleep(1)
            timeout -= 1

        if self.wanted_state != self.x_running:
            raise FailedStartingXServerError()

    def startx(self):
        self._is_ready(60)
        self.wanted_state = True
        if self.wanted_state == True and self.x_running == False:
            time.sleep(20)
        # wait up to 60 seconds for X to start
        self._is_switched(60)

    def killx(self):
        self._is_ready(60)
        self.wanted_state = False
        # wait up to 60 seconds for X to shut down
        self._is_switched(60)

    def switch_x_server(self, enable):
        try:
            if enable:
                self.startx()
            else:
                self.killx()
        except FailedStartingXServerError:
            if enable:
                error_text = "Could not start X server."
            else:
                error_text = "Could not stop X server."
            log.info("IGNORING EXCEPTION: %s" % error_text)
            log.info("Rebooting.")
            raise RebootNeededError


class LrbConsole(object):
    """ A class that opens and does a non-blocking read on a serial device """

    def __init__(self, ttyname, log_file, task_id):
        import serial
        self.serial = None
        self.log_file = log_file
        if os.path.exists(ttyname):
            try:
                self.serial = serial.Serial(port=ttyname,
                                            baudrate=115200,
                                            bytesize=serial.EIGHTBITS,
                                            parity=serial.PARITY_NONE,
                                            stopbits=serial.STOPBITS_ONE,
                                            timeout=None,
                                            xonxoff=0,  # software flow control
                                            rtscts=1)  # hardware flow control
            except serial.SerialException:
                log.exception("some problem with serial")
        if self.serial:
            log_file.write("Task id %s. " % str(task_id))
            log_file.write("Beginning console dump %s.\n" % str(ttyname))
        else:
            log_file.write("Task id %s. " % str(task_id))
            log_file.write("Failed opening console %s.\n" % str(ttyname))

    def __del__(self):
        if self.serial:
            self.serial.close()

    def _read(self):
        if self.serial:
            data = self.serial.read(self.serial.inWaiting())
            return data
        else:
            return ""

    def dumps(self, prepend_text):
        self.log_file.write(prepend_text)
        self.log_file.write(self._read())


def rm_tree(directory):
    path = os.path.abspath(directory)

    if checks.is_system("Linux", "Darwin", "FreeBSD", "VMkernel"):
        if checks.is_android():
            rm = "busybox rm"
        else:
            rm = "rm"
        txt, ret = exec_with_timeout("%s -rf %s" % (rm, path), 16, shell=True)
        if ret != 0:
            for _ in range(2):
                if os.path.exists(path):
                    txt, ret = exec_with_timeout("sudo %s -rf %s" % (rm, path), 16, shell=True)
                    if ret == 0 or (not os.path.exists(path)) or ("No such file or directory" in txt):
                        ret = 0
                        break
        if ret != 0:
            raise Exception("Deleting directory %s failed: %s" % (path, txt))
    else:
        txt, ret = exec_with_timeout("cmd.exe /c rd %s /Q /S" % path, 60)
        # Additional message for Win10
        if ret != 0 or 'Access is denied' in txt or 'cannot access the file' in txt:
            if ret != 0:
                for _ in range(2):
                    _kill_file_handle(path)
                    if os.path.exists(path):
                        txt, ret = exec_with_timeout("cmd.exe /c rd %s /Q /S" % path, 60)
                        if ret == 0 or (not os.path.exists(path)) or ('cannot find' in txt):
                            ret = 0
                            break
            if ret != 0:
                raise Exception("Deleting directory %s failed: %s" % (path, txt))


def get_task_path(task_id):
    return u"%04d/%04d" % (task_id // 1000, task_id % 1000)


def fwrite(fname, txt, flush=False, encoding='utf-8'):
    with io.open(fname, "wb") as f:
        f.write(ensure_bytes(txt, encoding))
        if flush:
            sync_fh(f)


def fappend(fname, txt, encoding='utf-8'):
    with io.open(fname, "ab") as f:
        f.write(ensure_bytes(txt, encoding))
        sync_fh(f)


def fwritelines(fname, lines, encoding='utf-8'):
    with io.open(fname, "wb") as f:
        lines = (ensure_bytes(l, encoding) for l in lines)
        f.writelines(lines)
        sync_fh(f)


def sync_fh(f):
    f.flush()
    os.fsync(f.fileno())
    if checks.is_macos():
        # f.flush() and os.fsync(f.fileno()) may fail on macOs
        # https://developer.apple.com/legacy/library/documentation/Darwin/Reference/ManPages/man2/fsync.2.html
        import fcntl
        import errno
        try:
            fcntl.fcntl(f, fcntl.F_FULLFSYNC)
        except (IOError, OSError) as exc:
            # operation is not supported when file is located on smbfs
            # let's silence this case and re-raise any other exception
            if exc.errno != errno.ENOTSUP:
                raise


def fread(fname, encoding='utf-8'):
    with io.open(fname, "rb") as f:
        if encoding:
            return str(f.read().decode(encoding))
        return f.read()


def freadlines(fname, encoding='utf-8'):
    with io.open(fname, "rb") as f:
        return [str(l.decode(encoding)) for l in f.readlines()]


def fread_by_line(fname, encoding='utf-8'):
    with io.open(fname, 'rb') as f:
        for line in f:
            yield str(line.decode(encoding))


def sizeof_fmt(num, suffix='B'):
    for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)


# The two's complement function
def complement(n):
    if n < (1 << 31):
        return n
    else:
        return int(n - (1 << 32))


def join_non_strings(separator, iterator_with_non_strings):
    return separator.join(str(value) for value in iterator_with_non_strings)


def str_join(separator, *args):
    return join_non_strings(separator, args)


def profile(func):
    """ Decorator for debug that measures function execution time """

    def timeit(*args, **kwargs):
        atime = time.time()
        result = func(*args, **kwargs)
        btime = time.time()
        arg_str = join_non_strings(', ', args)
        kwarg_str = ', '.join('{}={}'.format(k, v) for k, v in kwargs)
        log.info("Func %s(%s, %s) took %f sec.", func.__name__, arg_str, kwarg_str, btime - atime)
        return result

    return timeit


def timedelta_total_seconds(timedelta):
    """
    Return the total number of seconds contained in the duration.
    Note that for very large time intervals (greater than 270 years on most
    platforms) this method will lose microsecond accuracy.

    New in version 2.7.

    http://docs.python.org/library/datetime.html#datetime.timedelta
    """
    return (timedelta.microseconds + (timedelta.seconds + timedelta.days * 24 * 3600) * 10 ** 6) / 10 ** 6


def get_datetimes_in_intervals(start_time, **kwargs):
    current = start_time
    interval = datetime.timedelta(**kwargs)
    while True:
        current += interval
        yield current


def exec_dbg_view_start(path, log_name):
    log.info("Starting DebugView.")
    et = ExecThread(os.environ['USERPROFILE'] + "\\Desktop\\Dbgview.exe /t /l " + str(path) + "\\logs\\" + str(log_name) + "_dbgview.log", False, None, None)
    et.start()
    return et


def exec_dbg_view_stop(et):
    log.info("Closing DebugView.")
    if os.path.exists(os.environ['SYSTEMDRIVE'] + "\\dbgview_enable.txt"):
        os.system("del %s\\dbgview_enable.txt /Q /F" % os.environ['SYSTEMDRIVE'])
    kill_process(et, True)


def find_files(file_pattern, start_directory=''):
    """
    Helper utility method to search for a file starting at a path and then
    searching through all sub-directories for all files that match the input
    pattern.

    If no starting directory is provided, the searching will begin at the
    current working directory.
    """
    file_list = []
    if not start_directory:
        start_directory = os.curdir
    for path, _, files in os.walk(start_directory):
        for file_name in fnmatch.filter(files, file_pattern):
            file_list.append(os.path.join(path, file_name))
    return file_list


def unzip_file(destination_path, zip_file_path):
    """
    Unzip a zip file to the destination directory
    """
    if not zipfile.is_zipfile(zip_file_path):
        raise Exception("%s is not a valid zip file" % zip_file_path)
    zip_file = zipfile.ZipFile(zip_file_path)
    for fname in zip_file.namelist():
        f = join(destination_path, fname)
        d = os.path.dirname(f)
        if not os.access(d, os.F_OK):
            os.makedirs(d)
        fdata = zip_file.read(fname)
        fwrite(f, fdata)
    zip_file.close()
    return destination_path


def zip_extractall(zip_file_name, dst):
    """
    Extract all files from zip file and retrieve rwx permissions
    """
    z = zipfile.ZipFile(zip_file_name, "r")
    z.extractall(dst)
    for info in z.infolist():
        os.chmod(join(dst, info.filename), info.external_attr >> 16)
    z.close()


def binary_receiver(destination_file_path, package_id, package_count, package):
    """
    Receive one package per call and append to the destination_file_path file.
    The sender must send the package in the correct package_id sequence for the
    file to append into an expected file.
    """

    # check for destination file, create if it does not exist
    if not os.path.exists(os.path.dirname(destination_file_path)):
        os.mkdir(os.path.dirname(destination_file_path))

    # remove any existing file.
    if os.path.exists(destination_file_path) and package_id == 1:
        os.unlink(destination_file_path)

    if not 0 < package_id <= package_count:
        raise Exception("Package id is not within the expected range")

    fappend(destination_file_path, package.data)
    if package_id < package_count:
        return None
    else:
        return destination_file_path


def find_cwrsync():
    """
    Function checks if cwrsync is installed in system,
    if so return root directory path, else None
    """
    for program_files in ["Program Files", "Program Files (x86)"]:
        path = join(os.environ['SYSTEMDRIVE'], program_files, "cwRsync")
        if os.path.exists(path):
            return path
    return None


def prepare_cwrsync_cmd():
    """
    Check if cwrsync is enabled and "master" cwrsync batch file exists.
    If so, read, cut unnecessary line with comments and thrash lines.
    Return string with multiline cwrsync initialization procedure,
    ready for appending, cwrsync commands.
    """
    cwrsync_root = find_cwrsync()
    if not cwrsync_root:
        return None
    cwrsync_cmd_path = join(cwrsync_root, "cwrsync.cmd")
    if not os.path.exists(cwrsync_cmd_path):
        return None

    cwrsync_cmd = fread(cwrsync_cmd_path)
    # remove unnecessary lines
    # Batch comments, rsync commands, rd command; empty lines
    regex_list = (
        re.compile("^REM(.)*\n?", re.MULTILINE | re.U | re.I),
        re.compile("^rsync(.)*\n?", re.MULTILINE | re.U | re.I),
        re.compile("^rd(.)*\n?", re.MULTILINE | re.U | re.I),
        re.compile("^\s*$", re.MULTILINE | re.U),
    )
    for regexp in regex_list:
        cwrsync_cmd = re.sub(regexp, "", cwrsync_cmd)

    return cwrsync_cmd


def transform_to_rsync_path(path):
    return "/cygdrive/%s" % path.replace("\\", "/").replace(":", "/").replace("//", "/")


def normalize_filename(name):
    chars = " :\\<>(){}."
    newchars = "__________"
    trans_table = string.maketrans(chars, newchars)
    return name.translate(trans_table)


def normalize_whitespace(output):
    new_output = output.replace("  ", " ")
    while output != new_output:
        output = new_output
        new_output = output.replace("  ", " ")
    return new_output


def remove_list_of_files(list_of_files):
    for f in list_of_files:
        if os.path.exists(f):
            if os.path.isdir(f):
                rm_tree(f)
            else:
                os.unlink(f)


def remove_read_only_win(path, recursive=False):
    cmd = "attrib -R %s%s /S" % (path, '\\*' if recursive else '')
    _, retcode = exec_with_timeout(cmd, 30, cwd="C:\\")
    return not retcode


def exec_local_remote(target, username, cmd, *args, **kwargs):
    if target == 'localhost':
        return exec_with_timeout(cmd, *args, **kwargs)
    ses = sshsession.Session(target, username)
    # ssh session requires only timeout, consider 1st argument or timeout key is timeout value
    try:
        timeout = args[0] if args else kwargs['timeout']
    except KeyError:
        timeout = 10
    output = ses.execute_command(cmd, timeout)
    ses.disconnect()
    if not output:
        return output, 1
    temp = ""
    for line in output.splitlines()[1:-1]:  # drop first and last line - prompts
        temp += line + '\n'
    return temp, 0


def cmp_files_size(file1, file2):
    return os.path.getsize(file1) == os.path.getsize(file2)


def sync_task_logs():
    # work dir should be task dir
    task = Task.load_from_file()
    dst = task.task['repo_results_dir']
    src = os.getcwd()
    try:
        copy_files(src, dst)
    except Exception:
        log.exception("exception ignored")


def ensure_dir(path):
    """Like mkdir -p
    """
    original_umask = os.umask(0)
    try:
        os.makedirs(path)
    except Exception:
        if not os.path.exists(path):
            raise
    finally:
        os.umask(original_umask)


def _mark_quota_exceeded(dst):
    log.info("Quota exceeded! Skipping copying remaining files")
    touch_files(os.path.join(dst, "QUOTA_EXCEEDED_NOT_ALL_FILES_COPIED"))


def copy_bytes_from_file(f, cut_file, allowed_bytes):
    buf_size = 1024 * 1024  # 1 MB
    with open(f, "rb") as src_fd:
        with open(cut_file, "wb+") as dst_fd:
            while allowed_bytes > 0:
                buf_size = min(buf_size, allowed_bytes)
                log.debug('writing %s bytes of src %s', buf_size, f)
                dst_fd.write(src_fd.read(buf_size))
                allowed_bytes -= buf_size


def _determine_count_and_exclusions(files_and_size, quota=None):
    excluded_files = []
    copied = 0
    if not quota:
        return len(files_and_size), excluded_files

    sorted_by_size = sorted(files_and_size, key=lambda size: size[1])

    for index, (f, size) in enumerate(sorted_by_size, 1):
        if size <= quota:
            copied += 1
            quota -= size
            continue
        else:
            allowed_bytes = quota
            cut_file = f + ".1"
            copy_bytes_from_file(f, cut_file, allowed_bytes)
            shutil.move(cut_file, f)

            for f, _ in sorted_by_size[index:]:
                excluded_files.append(f.split('/')[-1])
            break

    return copied, excluded_files


def copy_files_by_rsync(root_src_dir, root_target_dir, files_and_size, quota=None, srv_addr=None, from_serv_to_agent=False):
    log.info("Recursive copying files from %s to %s by RSYNC", root_src_dir, root_target_dir)
    copied, excluded_files = _determine_count_and_exclusions(files_and_size, quota=quota)

    with tempfile.NamedTemporaryFile(suffix='.txt') as tmp_file:
        tmp_file.writelines("%s\n" % file for file in excluded_files)
        tmp_file.flush()
        tmp_file.seek(0)

        if srv_addr is None:
            cmd = "rsync -prva --exclude-from='{}' {}/ {}/ ".format(tmp_file.name, root_src_dir, root_target_dir)
        elif from_serv_to_agent:
            cmd = "rsync -prva -e 'ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no' --exclude-from='{}' bertax@{}:{}/ {}/  " \
                .format(tmp_file.name, srv_addr, root_src_dir, root_target_dir)
        else:
            cmd = "rsync -prva -e 'ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no' --exclude-from='{}' {}/ bertax@{}:{}/ "\
                .format(tmp_file.name, root_src_dir, srv_addr, root_target_dir)

        output, retcode = exec_with_timeout(cmd, 10000, shell=True)
        log.info(output)
        if retcode != 0:
            raise Exception("Problem during transfer files by rsync with error code {}".format(retcode))

    return copied


def copy_files(src, dst, files_equal=cmp_files_size, ignore_errors=False, quota=None, srv_addr=None, from_serv_to_agent=False):
    src = os.path.abspath(src)
    dst = os.path.abspath(dst)
    quota_info = "%s MB" % (quota / 1024.0 ** 2) if quota else "disabled"
    log.info("copying files from %s to %s, quota: %s " % (src, dst, quota_info))
    copied = 0
    total_files = 0
    files_and_size = []

    for dirpath, _, filenames in os.walk(src):
        if quota is not None and quota <= 0:
            _mark_quota_exceeded(dst)
            break

        relative_src_dir = os.path.relpath(dirpath, src)
        target_dir = os.path.abspath(os.path.join(dst, relative_src_dir))

        try:
            ensure_dir(target_dir)
        except (IOError, OSError):
            log.exception("Unable to create dir: %s" % target_dir)
            if not ignore_errors:
                raise
            continue

        for f in filenames:
            if f.endswith(".pyc") or f == '.coverage':
                continue

            total_files += 1
            src_file = os.path.join(dirpath, f)
            target_file = os.path.join(target_dir, f)
            if os.path.isdir(src_file):  # weirdly this is possible
                log.warning("File system error: directory %s listed as file." % src_file)
            if (checks.is_macos() or checks.is_linux()) and os.path.exists(target_file):
                if os.path.samefile(src_file, target_file):
                    continue
            if not os.path.exists(target_file) or not files_equal(src_file, target_file):
                try:
                    if USE_RSYNC_FOR_COPY == 0:
                        log.info("copy from %s to %s" % (src_file, target_file))
                        bytes_copied = copy_file_with_quota(src_file, target_file, quota)
                    else:
                        bytes_copied = 0
                        size = os.path.getsize(src_file)
                        files_and_size.append((src_file, size))

                    copied += 1
                    quota = quota - bytes_copied if quota is not None else None
                except (IOError, OSError):
                    log.exception("Problem with file copying")
                    # cannot truncate hidden files on Windows
                    try:
                        time.sleep(1)
                        os.unlink(target_file)
                        if USE_RSYNC_FOR_COPY == 0:
                            bytes_copied = copy_file_with_quota(src_file, target_file, quota)

                        copied += 1
                        quota = quota - bytes_copied if quota is not None else None
                    except (IOError, OSError):
                        if not ignore_errors:
                            raise
                        log.exception("Copying file ignored")

                if quota is not None and quota <= 0:
                    _mark_quota_exceeded(dst)
                    break

    if USE_RSYNC_FOR_COPY == 1:
        copied = copy_files_by_rsync(src, dst, files_and_size, quota, srv_addr, from_serv_to_agent)
    if copied == 0:
        log.info("no files copied out of %d" % total_files)
    else:
        log.info("copied files %d" % copied)
    return copied > 0


def copy_files_w_checksum(src, dst, timeout=None, max_retries=2):
    """
    Generic function for copying dirs with pre-calculated files checksum
    <src>/checksums.md5 must be present in src dir
    using utils.dir_compute_md5() function is recommended for checksums.md5 file creation
    :param src: source dir - its contents will be copied to dst dir
    :param dst: destination dir - will be created if not present and populated with src contents
    :param timeout: timeout in seconds - will be passed to exec_with_timeout()
    :param max_retries: mex number to retry copying single file if checksum check fails
    :return: nothing on success, exception on fail
    """
    src = os.path.abspath(src)
    dst = os.path.abspath(dst)
    log.info("copying files with checksum from %s to %s", src, dst)
    copy_start_time = time.time()
    if timeout is None:
        timeout_from_size = get_folder_size(src) // 1000 // 1000  # assume speed not less than 1MB/sec
        timeout_from_files_count = _get_timeout_from_files_count(src)
        timeout = max([timeout_from_size, timeout_from_files_count])  # take bigger timeout
        log.info("Calculated timeout for downloading: %s seconds", timeout)

    if checks.is_android() or checks.is_yocto():
        real_src = src + '/*' if os.path.exists(dst) else src
        cmd = "cp -rf %s %s" % (real_src, dst)

    elif checks.is_linux() or checks.is_macos():
        cmd = "/usr/bin/rsync -av --delete %s/ %s" % (src, dst)

    elif checks.is_windows():
        cmd = "robocopy \"%s\" \"%s\" /MIR /Z" % (src, dst)

    else:
        cmd = ''
        log.error("Unsupported system: %s - using shutil lib", platform.system())
        if os.path.exists(dst):
            shutil.rmtree(dst)

        shutil.copytree(src, dst)

    if cmd:
        exec_with_timeout(cmd, timeout, shell=True)

    copy_end_time = time.time()
    checksum_file = os.path.join(src, "checksums.md5")
    if not os.path.isfile(checksum_file):
        log.info("No checksum file present - only copying files from %s to %s" % (src, dst))
        return  # no checksum to check

    # retrieve checksum for each file from src folder
    dict_checksum = {}
    with open(checksum_file, 'r') as check_file:
        checksums = check_file.read().split('\n')
        for checksum in checksums:
            try:
                split_checksum = checksum.split(' ', 1)
                if len(split_checksum) > 1:
                    file_rel_path = split_checksum[1].replace('\\', '/')
                    if file_rel_path == 'checksums.md5':  # we should ignore this file in checksum check
                        continue

                    dict_checksum[file_rel_path] = split_checksum[0]

            except:
                pass

    # find files with invalid checksum
    bad_files_list = list(dict_checksum.keys())
    for root, _, files in os.walk(dst):
        for one_file in files:
            file_path = os.path.join(root, one_file)
            file_rel_path = os.path.relpath(file_path, dst).replace('\\', '/')
            if file_rel_path == 'checksums.md5':  # we should ignore this file in checksum check
                continue

            if file_rel_path not in bad_files_list:
                log.warning("File %s present in dst but missing in checksums.md5", file_path)
                continue

            file_checksum = compute_md5(file_path)
            if file_checksum == dict_checksum[file_rel_path]:
                bad_files_list.remove(file_rel_path)

    verify_end_time = time.time()

    # retry copying for single files with bad checksum
    for _ in range(max_retries):
        for bad_file in reversed(bad_files_list):
            src_file = os.path.join(src, bad_file)
            dst_file = os.path.join(dst, bad_file)
            if os.path.isfile(bad_file):
                os.remove(bad_file)

            log.info("checksum invalid - retry copy from %s to %s", src_file, bad_file)
            shutil.copy(src_file, dst_file)
            file_checksum = compute_md5(dst_file)
            if file_checksum == dict_checksum[bad_file]:
                bad_files_list.remove(bad_file)

    log.debug("Copied in %.1fs. Verified in %.1fs", copy_end_time - copy_start_time, verify_end_time - copy_end_time)

    if len(bad_files_list) > 0:
        raise Exception("Cannot complete copying dir {0} to {1} after {2} retries.".format(src, dst, max_retries))

    log.info("Successful copying files with checksum from %s to %s", src, dst)


def _get_timeout_from_files_count(src):
    """Timeout is one second per file
    """
    count = 0
    for _, _, files in os.walk(src):
        count += len(files)
    return count


def touch_files(files=None):
    """
    Utility for creating empty files.
    It returns False if one of the files could not be created.
    """

    def make_empty_file(fp):
        try:
            if not os.path.exists(fp):
                with open(fp, 'w'):
                    log.info('Created empty file at: %s', fp)
                return True
            else:
                log.info('Touch not needed, %s already exists', fp)
                return True
        except Exception:
            err, ret = exec_with_timeout('sudo touch "%s"' % fp, 10, shell=True)
            if ret:
                log.error("File %s cannot be created. sudo touch output: %s", fp, err)
                return False
            log.info('Created empty file at: %s using sudo touch', fp)
            return True

    if files is None:
        return False

    if isinstance(files, string_types):
        make_empty_file(files)
        return True

    success = all([make_empty_file(f) for f in files])
    return success


def move_files(src, dst, skip_re=None):
    if not os.path.exists(dst):
        os.makedirs(dst)

    dst_base = os.path.basename(dst)

    for f in os.listdir(src):
        if f == dst_base or (skip_re and re.search(skip_re, f)):
            continue

        src_elem = os.path.join(src, f)
        shutil.move(src_elem, dst)


def correct_hostname(hostname):
    # must be max 15 chars
    hostname = hostname[:15]

    # cannot have any of this chars: `~!@#\$%\^&\*()=\+_[\]{}\\\|;:\.\'",<>/\ ?
    m = re.findall(r'([`~!@#\$%\^&\*()=\+_[\]{}\\\|;:\.\'",<>/\? ])', hostname)
    if m:
        for un_char in set(m):
            hostname = hostname.replace(un_char, '-')

    return hostname


def compute_md5(fpath):
    h = hashlib.md5()
    with open(fpath, 'rb') as f:
        while True:
            block = f.read()
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def dir_compute_md5(root_dir):
    """
    Calculate md5 checksum for every file in directory and store these in text file
    :param root_dir: directory to start searching for files, here checksum file is stored
    """
    with open(os.path.join(root_dir, 'checksums.md5'), 'w+') as checksum_file:
        for root, _, files in os.walk(root_dir):
            for one_file in files:
                rfile = os.path.join(root, one_file)
                checksum_file.write('{0} {1}\n'.format(compute_md5(rfile), os.path.relpath(rfile, root_dir)))


class _Method(object):
    """
    Two classes _Method and Server are used to handle network
    related exceptions on the Agent side.
    """

    def __init__(self, srv, name):
        self.__srv = srv
        self.__name = name

    def __getattr__(self, name):
        return _Method(self.__srv, "%s.%s" % (self.__name, name))

    def __call__(self, *args, **kwargs):
        t0 = datetime.datetime.now()
        wait_time = 1
        while True:
            try:
                return getattr(self.__srv, self.__name)(*args, **kwargs)

            except xmlrpclib.ProtocolError:
                log.exception("IGNORING XML-RPC ProtocolError")

            except socket.error as e:
                # Codes description:
                #     32 - 'Broken pipe'
                #     100 - 'Network is down'
                #     101 - 'Network is unreachable'
                #     110 - 'Connection timed out'
                #     111 - 'Connection refused'
                #     112 - 'Host is down'
                #     113 - 'No route to host'
                #     10053 - 'An established connection was aborted by the software in your host machine'
                #     10054 - An existing connection was forcibly closed by the remote host
                #     10060 - 'Connection timed out'
                #     10061 - 'No connection could be made because the target machine actively refused it'
                if e.errno not in (32, 100, 101, 110, 111, 112, 113, 10053, 10054, 10060, 10061):
                    # connection error, operation timed out
                    raise

                log.info("XML-RPC operation status for %s: %s, retrying", self.__name, e.strerror)
                time.sleep(wait_time)
                if datetime.datetime.now() - t0 > datetime.timedelta(minutes=consts.NETWORK_TIMEOUT):
                    if e.errno not in (111, 10061):
                        raise NetworkError("Network timeout")

                    # berta - controller down
                    wait_time = 20


class Server(object):
    """
    Two classes _Method and Server are used to handle network
    related exceptions on the Agent side.
    """

    def __init__(self, srv):
        self.srv = srv

    def __getattr__(self, attr):
        if attr[0] == '_':
            return getattr(self, attr)
        else:
            return _Method(self.srv, attr)


def dumpstacks_to_str():
    id2name = dict([(th.ident, th.name) for th in threading.enumerate()])
    code = []
    for threadId, stack in sys._current_frames().items():  # pylint: disable=W0212
        code.append("\n# Thread: %s(%d)" % (id2name.get(threadId, ""), threadId))
        for filename, lineno, name, line in traceback.extract_stack(stack):
            code.append('File: "%s", line %d, in %s' % (filename, lineno, name))
            if line:
                code.append("  %s" % (line.strip()))

    txt = "\n".join(code)
    return txt


def dumpstacks(_, __):
    txt = dumpstacks_to_str()
    print(txt)
    log.info(txt)


# retry decorator from wiki.python.org/moin/PythonDecoratorLibrary
# and https://gist.github.com/2570004
#
# Copyright 2012 by Jeff Laughlin Consulting LLC
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


def retries(max_tries, delay=1, backoff=2, exceptions=(Exception,), hook=None):
    """Function decorator implementing retrying logic.

    delay: Sleep this many seconds * backoff * try number after failure
    backoff: Multiply delay by this factor after each failure
    exceptions: A tuple of exception classes; default (Exception,)
    hook: A function with the signature myhook(tries_remaining, exception);
          default None

    The decorator will call the function up to max_tries times if it raises
    an exception.

    By default it catches instances of the Exception class and subclasses.
    This will recover after all but the most fatal errors. You may specify a
    custom tuple of exception classes with the 'exceptions' argument; the
    function will only be retried if it raises one of the specified
    exceptions.

    Additionally you may specify a hook function which will be called prior
    to retrying with the number of remaining tries and the exception instance;
    see given example. This is primarily intended to give the opportunity to
    log the failure. Hook is not called after failure if no retries remain.
    """

    def dec(func):
        def f2(*args, **kwargs):
            mydelay = delay
            for tries_remaining in range(max_tries, 0, -1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    if tries_remaining == 1:
                        raise
                    if hook:
                        hook(tries_remaining, e, mydelay)
                    time.sleep(mydelay)
                    mydelay *= backoff

        return f2

    return dec


class HtmlStripper(html_parser.HTMLParser):
    def __init__(self):
        html_parser.HTMLParser.__init__(self)
        self.fed = []

    def handle_data(self, d):
        self.fed.append(d)

    def get_data(self):
        return ''.join(self.fed)


def strip_html(html):
    stripper = HtmlStripper()
    stripper.feed(html)
    return stripper.get_data()


def _set_time_unix(current_time):
    date = "%02d%02d" % (current_time.month, current_time.day)
    time_ = "%02d%02d" % (current_time.hour, current_time.minute)
    year = "%04d" % current_time.year
    seconds = ".%02d" % current_time.second
    if checks.is_freebsd():
        date_string = "".join([year, date, time_, seconds])
    else:
        date_string = "".join([date, time_, year, seconds])

    txt, ret = exec_with_timeout("sudo date %s" % date_string, 5, shell=True)
    if ret != 0:
        log.warning("Failed to set date:\n%s" % txt)
        return


def _set_time_lx(current_time):
    if os.path.exists('/etc/init.d/ntp'):
        time_before_ntp = datetime.datetime.now()
        txt, ret = exec_with_timeout("sudo /etc/init.d/ntp stop", 15, shell=True)
        if ret != 0:
            log.error("Failed stopping NTP:\n%s", txt)
            # correct the time for the duration of stopping NTP
        current_time += datetime.datetime.now() - time_before_ntp

    _set_time_unix(current_time)

    txt, ret = exec_with_timeout("sudo /sbin/hwclock --systohc", 5, shell=True)
    if ret != 0:
        log.warning("Failed to set hardware clock:\n%s" % txt)
        return


def _set_time_win(current_time):
    try:
        import win32api  # pylint: disable=F0401
        win32api.SetLocalTime(current_time)
    except ImportError:
        log.error("Setting time failed")
    except Exception:
        log.exception("Setting time failed")


def _set_time_android(current_time):
    flavour_name = checks.get_flavour_name_lx()
    if "MCG" in flavour_name:
        date_string = "%04d%02d%02d%02d%02d.%02d" % (current_time.year, current_time.month, current_time.day, current_time.hour,
                                                     current_time.minute, current_time.second)
        tool = "busybox date"
    else:
        date_string = "%04d%02d%02d.%02d%02d%02d" % (current_time.year, current_time.month, current_time.day, current_time.hour,
                                                     current_time.minute, current_time.second)
        tool = "date"
    txt, ret = exec_with_timeout("sudo %s -s %s" % (tool, date_string), 5, shell=True)
    if ret != 0:
        log.warning("Failed to set date:\n%s" % txt)


def _getprop(prop_name):
    txt, ret = exec_with_timeout("getprop %s " % prop_name, 5, shell=True)
    if ret != 0 or txt is None:
        log.warning("Cannot read '%s' property: %s" % (prop_name, txt))
        return ''
    return txt.replace("\n", "")


def set_time(current_time):
    if checks.is_windows():
        return _set_time_win(current_time)
    elif checks.is_system("Darwin", "FreeBSD"):
        return _set_time_unix(current_time)
    elif checks.is_android():
        return _set_time_android(current_time)
    else:
        return _set_time_lx(current_time)


def test_for_non_acsii(text):
    """

    :param str text: the text to test
    :raise ValueError when non ASCII character is found
    """
    encoded = None
    try:
        encoded = text.encode(encoding='ascii')
        assert len(text) == len(encoded)

    except (TypeError, AttributeError, UnicodeEncodeError):
        log.exception('encode failure')
        raise ValueError("Non ASCII character found in %s" % text)

    except AssertionError:
        log.exception('length mismatch:\n%s\n%s', text, encoded)
        raise ValueError("Non ASCII character found in %s" % text)


def remove_non_ascii(text, replace_to=r' '):
    return re.sub(r'[^\x00-\x7f]', replace_to, text)


def _check_manifest(src_dir):
    manifest_file = join(src_dir, "manifest.txt")
    manifest = fread(manifest_file)
    lines = manifest.split("\n")
    src_files_num = int(lines[0])
    files_md5 = {}
    for f in lines[1:]:
        if f.strip() == "":
            continue
        md5, fp = f.split(" ")
        files_md5[fp] = md5

    count = 0
    for path, _, files in os.walk(src_dir):
        subpath = path.replace(src_dir, "").replace("\\", "/")
        if len(subpath) >= 1 and subpath[0] == "/":
            subpath = subpath[1:]

        for f in files:
            if f == "manifest.txt":
                continue

            count += 1
            if subpath:
                fp = "%s/%s" % (subpath, f)
            else:
                fp = f

            if fp not in files_md5:
                log.warning("file %s not found in manifest", fp)
                return False

            md5 = compute_md5(os.path.join(path, f))
            if files_md5[fp] != md5:
                log.warning("file %s has wrong md5: %s != %s", f, files_md5[fp], md5)
                return False

    if count != src_files_num:
        log.warning("files number different than in manifest %d != %d", count, src_files_num)
        return False

    return True


def update_agent_files(latest_zip, dst, var_dir, use_sudo=False):
    try:
        ensure_dir(dst)
    except:
        log.warning("Something wrong with permissions to {}.".format(dst))

    prefix = latest_zip.rsplit(os.sep, 1)[1].split(".")[0] + "-"
    temp_dir = tempfile.mkdtemp(prefix=prefix, dir=var_dir)
    local_zip_file = join(var_dir, latest_zip.rsplit(os.sep, 1)[1])
    if os.path.exists(local_zip_file):
        os.chmod(local_zip_file, stat.S_IWUSR)
        os.unlink(local_zip_file)

    # in some configurations (notably Media Berta in FM)
    # files are intermittently unavailable for some time after share is mounted
    if not os.path.exists(latest_zip):
        time.sleep(3)
    try:
        with open(latest_zip):
            pass
    except IOError:
        time.sleep(3)

    log.info("starting copy zipfile from %s to %s" % (latest_zip, local_zip_file))
    shutil.copy(latest_zip, local_zip_file)
    log.info("extracting zip file %s" % local_zip_file)
    zip_extractall(local_zip_file, temp_dir)
    try:
        if not _check_manifest(temp_dir):
            log.warning("problems with manifest, upgrade skipped")
            return False

        if use_sudo:
            _, copied = exec_with_timeout("sudo cp -r %s/* %s" % (temp_dir, dst), 180, shell=True)
        else:
            copied = copy_files(temp_dir, dst, lambda a, b: False, from_serv_to_agent=True)
    finally:
        if sys.platform.startswith('win'):
            os.chmod(temp_dir, stat.S_IWUSR)
            os.chmod(local_zip_file, stat.S_IWUSR)
        shutil.rmtree(temp_dir)
        os.unlink(local_zip_file)

    return copied


def add_to_library_path(path):
    if not checks.is_linux():
        raise Exception("Function 'add_to_library_path' is not implemented for OSes other than Linux")
    current_library_path = ""
    if "LD_LIBRARY_PATH" in os.environ.keys():
        current_library_path = os.environ["LD_LIBRARY_PATH"]
    if path in current_library_path:
        log.info("Path: %s already is in LD_LIBRARY_PATH variable" % path)
        return
    os.environ["LD_LIBRARY_PATH"] = "%s:%s" % (current_library_path, path)
    os.system("echo $LD_LIBRARY_PATH")
    os.system("sudo ldconfig")


def sync_log(src, dest_log_path, src_is_file=True, dst_offset=0):
    try:
        if src_is_file:
            if not os.path.exists(src):
                log.warning("src log %s is missing" % src)
                return

            src_size = os.path.getsize(src)
        else:
            src_size = len(src)

        if os.path.exists(dest_log_path):
            dest_size = os.path.getsize(dest_log_path)
        else:
            dest_size = 0

        if src_size == dest_size - dst_offset:
            return

        if src_is_file:
            with open(src, "rb") as src_log:
                if dest_size - dst_offset > 0:
                    src_log.seek(dest_size - dst_offset)
                data = src_log.read()
        else:
            data = src[dest_size - dst_offset:]
        fappend(dest_log_path, data)
        log.info("log synced %s", dest_log_path)
        return
    except (IOError, OSError):
        log.exception('Agent encountered following problem with copying log "%s" to share "%s"', src, dest_log_path)
        return


def pidof(cmd_line):
    if not checks.is_linux():
        log.error("Function 'utils.pidof' is not implemented for OSes other than Linux")
        return None
    cmd = 'pgrep %s'
    if checks.is_yocto():
        cmd = 'busybox pidof %s'
    out, _ = exec_with_timeout(cmd % cmd_line, timeout=10, shell=True, cwd=os.getcwd())
    if len(out) == 0:
        log.info("No process found for %s" % cmd_line)
        return None
    if checks.is_yocto():
        return out.split(' ')
    return out.split('\n')


def load_json_file(path, message=None, check_existence=False):
    path = os.path.abspath(path)
    if message:
        log.info(message, path)
    if check_existence and not os.path.exists(path):
        return None
    with io.open(path, encoding='utf-8') as fp:
        return json.load(fp)


def is_os_dirty(agent_var_dir_path):
    return os.path.exists(join(agent_var_dir_path, consts.AGENT_OS_DIRTY_FILE))


def mark_os_dirty(agent_var_dir_path):
    with open(join(agent_var_dir_path, consts.AGENT_OS_DIRTY_FILE), 'w') as mark_dirty_file:
        mark_dirty_file.write('reload os')  # TODO: convert to fwrite


def _cleanup_output(txt):
    return txt.strip().replace('\n', '').replace('\r', '')


def load_cfg(config_file, defaults=None):
    """
    Load ini files with defaults section for RawConfigParser
    :param config_file: path to file
    :param defaults: None or dict, ex. {'team_name': None}
    :return: RawConfigParser object
    """

    config = RawConfigParser(defaults)
    try:
        with open(config_file) as f:
            config.readfp(f)

    except (ConfigParserError, IOError):
        log.error("Invalid config file '%s'", config_file)

    return config


class Task(object):
    TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"

    @classmethod
    def load_from_file(cls, file_path='task.json', full_path=None, check_existence=False):
        if full_path:
            file_path = os.path.join(full_path, file_path)
        data = load_json_file(file_path, message="Loading Task as JSON from: %s", check_existence=check_existence)
        if data is None:
            return None
        return cls(data)

    def __init__(self, task):
        self.task = task
        self.config = task['config']
        self.jobs = task['jobs']
        self.result_path = get_task_path(self.get_id())
        self._task_dir = task.get("task_dir")

        start_time = self.task.setdefault("start_time", datetime.datetime.now())
        if isinstance(start_time, string_types):
            self.task['start_time'] = datetime.datetime.strptime(start_time, self.TIME_FORMAT)

    def __getitem__(self, key):
        return self.task[key]

    def get(self, key):
        return self.task[key]

    def get_id(self):
        return self.task["task_id"]

    @property
    def submitted_by(self):
        return self.task.get('submitted_by', '')

    @property
    def current_job_idx(self):
        return self.task["current_job"]

    @property
    def current_job(self):
        return self.jobs[self.current_job_idx]

    @property
    def start_time(self):
        return self.task['start_time']

    def set_current_job(self, idx):
        self.task["current_job"] = idx

    def get_job_by_search(self, search):
        try:
            return next(job for job in self.jobs if search(job))
        except StopIteration:
            raise LookupError('Failed to find job')

    def get_job_by_type(self, job_type):
        try:
            return self.get_job_by_search(lambda job: job['job_type'] == job_type)
        except LookupError:
            raise Exception("Cannot find %s job in task %s" % (job_type, str(self.task)))

    def get_sut_job(self):
        return self.get_job_by_type('sut')

    def get_system_job(self):
        try:
            return self.get_job_by_type('system')
        except:
            return self.get_job_by_type('sut')

    def get_test_job(self):
        return self.get_job_by_type('test')

    def get_service_job(self):
        try:
            return self.get_job_by_type('service')
        except:
            return None

    def get_dir(self):
        return self._task_dir

    def get_params(self):
        return self.task['params']

    def dump_json(self, custom_path=None):
        f = os.path.abspath(custom_path if custom_path else os.path.join(self.get_dir(), "task.json"))
        log.info("Saving Task %s to json: %s", self.get_id(), f)
        as_json = self.as_json(True)
        fwrite(f, as_json, flush=True)
        try:
            load_json_file(f)
        except Exception:
            log.exception("JSON file %s is corrupted.  JSON content:\n%s", f, as_json)

        return f

    def as_json(self, pretty_format=False):
        task = copy.deepcopy(self.task)
        task['start_time'] = task['start_time'].strftime(self.TIME_FORMAT)
        if pretty_format:
            return json.dumps(task, sort_keys=False, indent=4, separators=(',', ': '))
        return json.dumps(task)

    def as_dict(self):
        return self.task

    def pop_job(self, job):
        def update(keeper):
            if keeper['job_id'] > job['job_id']:
                keeper['job_id'] -= 1
            return keeper

        self.jobs[:] = [update(j) for j in self.jobs if j != job]

    def get_config_names(self, pattern='', *ignore_endings):
        return filter_names_not_bad_endings(self.config.keys(), pattern, *ignore_endings)

    def get_machine_params(self, as_dict=False):
        """Reads machine params"""
        params_string = self.task['params']
        if as_dict:
            return text_to_dict(params_string)

        return params_string


def get_folder_size(p):
    p = safe_bytes2string(p)
    p = p.encode('utf8')
    if not os.path.exists(p):
        return 0
    prepend = partial(os.path.join, p)
    return sum([(os.path.getsize(f) if os.path.isfile(f) else get_folder_size(f)) for f in [prepend(pa) for pa in os.listdir(p)]])


def get_truncated_folder_size_in_kilobytes(path):
    logs_size = get_folder_size(path) / 1000
    if logs_size > consts.MYSQL_SIGNED_INT_MAX:
        log.info("Logs size overflow (%d), truncating to %d", logs_size, consts.MYSQL_SIGNED_INT_MAX)
        logs_size = consts.MYSQL_SIGNED_INT_MAX
    return logs_size


def get_free_disk_space(disk):
    # calculates free disk space in megabytes
    if disk is None:
        log.error("Disk name should be string, not None")
        return -1

    if checks.is_windows():
        free_bytes = ctypes.c_ulonglong(0)
        ctypes.windll.kernel32.GetDiskFreeSpaceExW(ctypes.c_wchar_p(disk), None, None, ctypes.pointer(free_bytes))
        return free_bytes.value // 1024 // 1024
    else:
        st = os.statvfs(disk)
        return st.f_bavail * st.f_frsize // 1024 // 1024


def force_remove_file(path):
    if checks.is_windows():
        cmd = "cmd /c DEL /F /Q \"%s\"" % path

    elif checks.is_linux() or checks.is_macos():
        cmd = "sudo rm -f %s" % path

    else:
        raise RuntimeError('Unsupported system {0}'.format(platform.system()))

    return exec_with_timeout(cmd, 300, shell=True)


def force_remove_dir(path):
    if checks.is_windows():
        cmd = "cmd /c RMDIR /S /Q \"%s\"" % path

    elif checks.is_linux():
        cmd = "sudo rm -rf %s" % path

    else:
        raise RuntimeError('Unsupported system {0}'.format(platform.system()))

    exec_with_timeout(cmd, 300, shell=True)


def set_hostname(hostname):
    if checks.is_presi_host():
        log.info("Agent presi proxy. Do not change hostname")
        return True
    if socket.gethostname() == hostname:
        log.info("Hostname %s already set." % hostname)
        return True
    if checks.is_windows():
        log.info("Changing hostname from '%s' to '%s'" % (socket.gethostname(), correct_hostname(hostname)))
        if checks.is_windows_server():
            exec_with_timeout("netdom RENAMECOMPUTER %s /NewName %s /Force" % (socket.gethostname(), correct_hostname(hostname)), 15, shell=True)
            # We need to reboot Hyper-V to make it work after changing hostname
            if checks.has_hyperv():
                raise RebootNeededError("Need to reboot to update hostname")
        set_reg_value("HKLM", "SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName",
                      "ComputerName", correct_hostname(hostname))
        set_reg_value("HKLM", "SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters",
                      "NV Hostname", correct_hostname(hostname))
        set_reg_value("HKLM", "SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters",
                      "Hostname", correct_hostname(hostname))
        return True
    elif checks.is_linux():
        if checks.is_rhel():
            exec_with_timeout("cat /etc/sysconfig/network | sed 's#HOSTNAME=.*#HOSTNAME=%s#g' > /tmp/newhostname" % hostname, 10, shell=True)
            exec_with_timeout("sudo cp /tmp/newhostname /etc/sysconfig/network", 10, shell=True)
        exec_with_timeout("sudo sh -c 'echo %s > /etc/hostname'" % hostname, 10, shell=True)
        exec_with_timeout("sudo hostname %s" % hostname, 10, shell=True)
        # Some androids do not have /etc/hosts
        if os.path.exists("/etc/hosts"):
            # some androids also do not have /tmp or have read-only filesystem
            try:
                hosts = fread("/etc/hosts")
                # Update /etc/hosts file to avoid 'unknown hostname' errors
                berta_entry = "Berta target name"
                new_hosts_entry = "\n127.0.0.1 %s # %s\n" % (hostname, berta_entry)
                old_hosts_entry = "\n127.0.0.1 .* # %s\n" % berta_entry
                if berta_entry in hosts:
                    hosts = re.sub(old_hosts_entry, new_hosts_entry, hosts)
                else:
                    hosts += new_hosts_entry
                fwrite("/tmp/hosts-updated", hosts)
                exec_with_timeout("sudo cp /tmp/hosts-updated /etc/hosts", 10, shell=True)
            except:
                log.info("Setting hostname on %s is not possible." % platform.system())
                return False
    elif checks.is_macos():
        exec_with_timeout("sudo scutil --set HostName " + str(hostname), 10, shell=True)
    else:
        log.info("Setting hostname on %s not implemented." % platform.system())
        return False


def is_presi(machine):
    if machine:
        try:
            if machine.controller and int(machine.power_socket) < 0:
                return True
        except:
            pass
    return False


def parse_cron_rule(cron_rule):
    return cron_rule.split()[:5]


def validate_cron_field(check_string, allowed_range, allowed_chars=None):
    if allowed_chars is None:
        allowed_chars = ('*', ',', '/', '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9')

    try:
        assert all(int(number) in allowed_range for number in re.findall(r'\d+', check_string))
        assert all(char in allowed_chars for char in check_string)

        substrings = check_string.split(' ')
        assert all(all(sub.count(char) < 2 for char in ('/', '*')) for sub in substrings)

    except (AssertionError, ValueError):
        return False

    else:
        return True


def validate_cron_fields(minutes, hours, days, months, dow):
    valid = True
    msg = None
    if not validate_cron_field(minutes, set(range(0, 60))):
        return False, 'Cron rule invalid, improper value in minutes: %s' % minutes
    if not validate_cron_field(hours, set(range(0, 24))):
        return False, 'Cron rule invalid, improper value in hours: %s' % hours
    if not validate_cron_field(days, set(range(1, 32))):
        return False, 'Cron rule invalid, improper value in days: %s' % days
    if not validate_cron_field(months, set(range(1, 13))):
        return False, 'Cron rule invalid, improper value in days: %s' % months
    if not validate_cron_field(dow, set(range(0, 7))):
        return False, 'Cron rule invalid, improper value in day of week: %s' % dow

    return valid, msg


def try_validate_cron_fields(minutes, hours, days, months, dow):
    try:
        valid, message = validate_cron_fields(minutes, hours, days, months, dow)
    except ValueError:
        raise ValueError('Cron rule invalid, improper format: %s %s %s %s %s' % (minutes, hours, days, months, dow))
    if not valid:
        raise ValueError(message)


def make_dev_image_path(user, machines_group, system):
    dev_image_path = '%s-%s-%s.dump' % (user, machines_group, system)
    dev_image_path = dev_image_path.replace(' ', '_')
    return dev_image_path


def sync_fs(path):
    if checks.is_windows():
        sync_ntfs(path)


def sync_ntfs(path):
    set_reg_value("HKCU", "Software\\Sysinternals\\Sync", "EulaAccepted", 1)
    sync = join(os.environ['BERTA_VAR_DIR'], '..', 'utils', 'sync.exe')
    drive, _ = os.path.splitdrive(path)
    drive = drive.rstrip(":")
    exec_with_timeout([sync, drive], timeout=10)


def truncate_file(path, size=0):
    if not os.path.exists(path):
        return

    if checks.is_windows():
        cmd = "C:\\berta\\utils\\trunc.exe %s %s" % (path, size)
        exec_with_timeout(cmd, 60, shell=True)
        return

    if checks.is_linux() and path == '/var/log/syslog':
        cmd = "sudo truncate -s %s %s" % (size, path)
        out, ret = exec_with_timeout(cmd, 60, shell=True)
    else:
        cmd = "truncate -s %s %s" % (size, path)
        out, ret = exec_with_timeout(cmd, 60, shell=True)

    log.debug('Truncate: ret %s, out:\n%s', ret, out)
    if ret and not size:
        exec_with_timeout("sudo rm %s" % path, 60, shell=True)
        exec_with_timeout("sudo touch %s" % path, 60, shell=True)


def validate_reboot_sequence(sequence):
    try:
        assert isinstance(sequence, string_types) and len(sequence) != 1
        parts = sequence.split()
        pattern = re.compile('^[xo]\d*$')
        assert sequence == u'' or all(pattern.match(x) for x in parts)
        return True

    except AssertionError:
        pass

    raise ValueError("Invalid custom reboot sequence")


# make sure that unpacking removes the extension or delete the file after
PACKERS_LX = {
    '.gz': 'gzip --decompress {0}',
    '.bz2': 'bunzip2 {0}',
    '.tar': 'tar xf {0} && rm --force {0}',
    '.zip': 'unzip {0} && rm --force {0}',
}


class UnpackingError(Exception):
    pass


def unpack(dir_path):
    """Unpack/uncompress a file in the destination.

    :param str | unicode dir_path: The path in which the file to unpack/uncompress is located
    :raises ValueError if there are too many files in the target path
    :raises UnpackingError if the unpacking/decompressing tool fails
    """
    if checks.is_linux():
        packers = PACKERS_LX
    else:
        raise NotImplementedError('utils.unpack is not implemented for {}'.format(checks.get_system()))

    exec_params = {
        'cwd': dir_path,
        'shell': True,
        'timeout': 5 * 60,
    }
    files = os.listdir(dir_path)
    for build_file in files:
        log.info('Trying to unpack %s in %s...', build_file, dir_path)
        while build_file in os.listdir(dir_path):
            try:
                packer_type, packer = next((pt, p) for pt, p in packers.items() if build_file.endswith(pt))
            except StopIteration:
                break
            cmd = exec_params['cmd'] = packer.format(build_file)
            output, ret = exec_with_timeout(**exec_params)
            if ret:
                raise UnpackingError("Unsuccessful unpacking with {} output:\n{}".format(cmd, output))
            build_file = build_file[:-len(packer_type)]


def is_dir_nonempty(path):
    """ Returns True if directory exists and is not empty (there are files/directories inside it).
        Otherwise returns False.
    """

    return os.path.exists(path) and len(os.listdir(path)) > 0


def kernel_cmdline_changed(agent_var_dir_path):
    return os.path.exists(join(agent_var_dir_path, consts.AGENT_KERNEL_CMDLINE_CHANGED))


def _sort_files_by_size(files):
    sorted_by_size = [(fd, os.path.getsize(fd)) for fd in files if os.path.isfile(fd)]
    return [file_size[0] for file_size in sorted(sorted_by_size, key=lambda x: x[1])]


def copy_agent_logs_with_quota(agent_logs_dir, dst, quota, srv_addr=None):
    """
    Copy most important agent logs. Truncate logs which are too big.
    It uses simple algorithm: copy small files firstly and then copy big files and truncate them.
    """

    task_files = get_files_matching_regexps(agent_logs_dir, consts.AGENT_LOG_FILES, full_path=True)
    # some agent logs are stored on share not in task's directory
    share_files = get_files_matching_regexps(dst, consts.AGENT_LOG_FILES, full_path=True)
    agent_logs = _sort_files_by_size(task_files + share_files)
    files_count = len(agent_logs)
    files_and_size = []
    file_size_sum = 0
    for i, log_file in enumerate(agent_logs):
        dst_path = os.path.join(dst, os.path.basename(log_file))
        available_avg_size = int(quota / (files_count - i))

        size = os.path.getsize(log_file)
        if log_file in task_files:
            if USE_RSYNC_FOR_COPY == 0:
                used_bytes = copy_file_with_quota(log_file, dst_path, available_avg_size, append_truncation_info=True)
            else:
                files_and_size.append((log_file, size))
                used_bytes = size
        else:
            if size > available_avg_size:
                truncate_file(log_file, available_avg_size)
                used_bytes = available_avg_size
                fappend(log_file, TRUNCATE_MARK)
            else:
                used_bytes = size

        quota -= used_bytes
        file_size_sum += used_bytes

    if USE_RSYNC_FOR_COPY == 1:
        copy_files_by_rsync(agent_logs_dir, dst, files_and_size, quota, srv_addr)

    remove_list_of_files(task_files)

    return file_size_sum


def copy_file_with_quota(src_file, target_file, quota, append_truncation_info=False):
    """
    If append_truncation_info = True, then the result file size will equal to:
    quota + len(TRUNCATE_MARK)
    """

    size = os.path.getsize(src_file)
    if not quota or size <= quota:
        log.debug('copy full file')
        shutil.copy2(src_file, target_file)
        return size

    buf_size = 1024 * 1024  # 1 MB
    allowed_bytes = quota
    with open(src_file, "rb") as src_fd:
        with open(target_file, "wb+") as dst_fd:
            while allowed_bytes > 0:
                buf_size = min(buf_size, allowed_bytes)
                log.debug('writing %s bytes of src %s', buf_size, src_file)
                dst_fd.write(src_fd.read(buf_size))
                allowed_bytes -= buf_size

            if append_truncation_info:
                log.debug('appending mark to dst %s', target_file)
                dst_fd.write(TRUNCATE_MARK)

    return quota


def get_files_matching_regexps(search_dir, regexp_list, full_path=False):
    """ Function a bit more powerful than glob.
        It is able to search files matching any of given regexps.
        It uses re module to match files.
    """

    result = []
    files_list = os.listdir(search_dir)
    for regexp in regexp_list:
        for filename in files_list:
            if re.match(regexp, filename):
                if full_path:
                    filename = os.path.join(search_dir, filename)
                result.append(filename)

    return result


def from_human_number(number):
    """ Translates human readable numbers into bytes
    """

    postfixes = ['KB', 'MB', 'GB', 'TB']
    number = number.upper()
    for index, postfix in enumerate(postfixes):
        if postfix in number:
            return int(float(number.replace(postfix, '')) * (1024 ** (index + 1)))

    return int(number)


def get_win_sysdrive_letter():
    return os.environ.get("SYSTEMDRIVE", "C:")


def get_remote_agent_conf():
    """Get remote agent config.

    :return: system, ip address
    :raise NoConfigAgentRemote: when config was not found
    """
    CONFIG_FILE = 'berta_agent_conf'
    CONFIG_FILES = ["/etc/{0}".format(CONFIG_FILE)]

    for config_file in CONFIG_FILES:
        if os.path.exists(config_file):
            with open(config_file) as data_file:
                config = json.load(data_file)
                if 'system' not in config or 'ip' not in config:
                    raise RuntimeError("Incorrect config: %s" % config)
                return config['system'], config['ip']
    raise NoConfigAgentRemote("No remote config for Agent")


def text_to_dict(text):
    """Parses line-separated 'key=val' pairs to a dict object"""

    d = {}
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            key, val = line.split('=', 1)
            key, val = key.strip(), val.strip()
            d[key] = val

    return d


def get_dmesg():
    if checks.is_windows():
        raise Exception("dmesg can be collected on unix systems")

    if checks.is_system("Darwin"):
        out, _ = exec_with_timeout("sudo dmesg", 10, shell=True)
        # clear kernel log buffer for OS X
        exec_with_timeout("sudo sysctl -w kern.msgbuf=1 && sudo sysctl -w kern.msgbuf=16384", 10, shell=True)
    elif checks.is_freebsd():
        out, _ = exec_with_timeout("sudo dmesg", 10, shell=True)
        # clear kernel log buffer for FreeBSD
        exec_with_timeout("sudo sysctl kern.msgbuf_clear=1", 10, shell=True)
    else:
        # clear kernel log buffer for Linux/Android
        out, _ = exec_with_timeout("sudo dmesg -c", 10, shell=True)

    return out


def berta_file(*paths):
    return join(os.environ["BERTA_AGENT_DIR"], *paths)


def is_smaps(pid):
    return os.path.exists('/proc/%s/smaps' % pid)


def _get_process_uss(process):
    return sum(m.private_dirty for m in process.memory_maps())


def _get_process_uss_with_recursive_children(process):
    return sum(_get_process_uss(child_p) for child_p in process.children()) + _get_process_uss(process)


def get_process_related_memory(process):
    # if smaps is available, use it to calculate uss memory consumed by the process and its children
    if is_smaps(process.pid):
        return _get_process_uss_with_recursive_children(process)
    # else, use only rss of the process itself
    return process.memory_info().rss


def filter_min(*args, **kwargs):
    ignore = kwargs.get('ignore', set())
    return min(arg for arg in args if arg not in ignore)


def filter_max(*args, **kwargs):
    ignore = kwargs.get('ignore', set())
    return max(arg for arg in args if arg not in ignore)


def get_string_size(_str):
    return len(_str.encode('utf-8'))


def truncate_list_to_quota(str_list, extra_size=0, quota=consts.MYSQL_TEXT_LENGTH):
    """
    :param str_list: list of strings
    :param extra_size: extra size occupied per list element
    :param quota: max size of string created from provided list
    :return: list of strings satisfying provided parameters
    """
    result_list = []
    remaining_size = quota
    for value in str_list:
        value_size = get_string_size(value) + extra_size
        remaining_size -= value_size
        if remaining_size < 0:
            break
        result_list.append(value)
    return result_list


def get_macos_nvram(name):
    if checks.is_macos():
        cmd = 'nvram %s' % name
        out, ret = exec_with_timeout(cmd, 10, shell=True)
        if ret == 0:
            return out.split()[-1]
    return None


def _limit_test_name_size(name):
    if len(name) > 255:
        name = "%s_%08x" % (name[:246], binascii.crc32(name if PY2 else name.encode()) & 0xffffffff)
    return name


def get_test_log_path(test_name):
    test_name = _limit_test_name_size(test_name)
    name = re.sub("[^A-Za-z0-9]", '_', test_name)
    return os.path.join('test_cases', name, ".".join((name, 'html')))


@contextmanager
def timer():
    data = {'start': datetime.datetime.now()}
    yield data
    data['end'] = end = datetime.datetime.now()
    data['delta'] = (end - data['start']).total_seconds()


def sleep(soft_sleep=0, hard_sleep=0):
    def outer(func):
        def wrapper(*args, **kwargs):
            with timer() as exec_time:
                result = func(*args, **kwargs)
            time.sleep(max(soft_sleep - exec_time['delta'], hard_sleep))
            return result

        return wrapper

    return outer


def make_unicode_or_none(value):
    if value:
        return make_unicode(value)
    return None


def make_bool_int_or_none(value):
    if value is None:
        return None
    return bool(int(value))


def make_long_or_none(value):
    if value:
        return integer_types[-1](value)
    return None


class StringIO(io.StringIO):

    def __init__(self, text=None, *args, **kwargs):
        if text is not None:
            text = make_unicode(text)
        super(StringIO, self).__init__(text, *args, **kwargs)

    def write(self, text):
        if text is None:
            return

        return super(StringIO, self).write(make_unicode(text))


class DummyStringIO(io.StringIO):

    def __init__(self, value=None, text=None, *args, **kwargs):
        super(DummyStringIO, self).__init__(text, *args, **kwargs)
        self.value = value

    def writelines(self, *args, **kwargs):
        pass

    def writable(self):
        return False

    def read(self, *args, **kwargs):
        return self.value

    def readable(self):
        return True

    def readline(self, *args, **kwargs):
        return self.value

    def readlines(self, *args, **kwargs):
        return [self.value]

    def write(self, *args, **kwargs):
        pass

    def getvalue(self, *args, **kwargs):
        return self.value


class Password(object):
    def __init__(self, value):
        self.__value = make_unicode(value)

    def __str__(self):
        return u'password hidden'

    def __repr__(self):
        return self.__str__()

    def retrieve(self):
        return self.__value


def unmarshaller_password(u, v):
    u.append(Password(v))
    u._value = 0


xmlrpclib.Unmarshaller.dispatch['password'] = unmarshaller_password
xmlrpclib.Marshaller.dispatch[Password] = lambda _, v, w: w("<value><password>%s</password></value>" % v.retrieve())
