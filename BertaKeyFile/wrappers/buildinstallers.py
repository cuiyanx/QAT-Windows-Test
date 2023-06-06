"""
Base build installers available in Berta.

An installer exposes two external methods: is_installed and install.
is_install should check if correct version of build is installed. If it
returns {'installed': False} then the install method is called. A driver
installer is provided in BuildInstaller.
"""
from __future__ import print_function, division, absolute_import
import logging
import shutil
try:
    import configparser
except ImportError:
    import ConfigParser as configparser
import os
import os.path
import re
import sys
import json
import traceback
import logs
from itertools import groupby

import checks
from data_utils import string_bool
import utils
import consts
from utils import join, exec_with_timeout, RebootNeededError, ShutdownNeededError, run_if_dunder_main
from job import Job
import repository
import httphelper
from wrappers import wrapper
from py2py3 import bytes2string, StringIO, DecodeError

log = logging.getLogger(__name__)


def run_wrapper(wrapper_class, extra_classes=None):
    with open("task.json") as f:
        task = json.load(f)
    task = utils.Task(task)

    class_ = wrapper_class
    if extra_classes:
        for c in extra_classes:
            if c.__name__ == task.current_job['scenario']:
                class_ = c
                break
    wrapper.setup_logging()
    logs.set_ctx(task=task.get_id())
    log.info('<>'*60)
    log.info("Starting %s installer" % class_.__name__)
    repo = repository.get_repo(task.current_job['var_dir'])
    wrp = class_(task.current_job['build_dest_dir'], task.current_job['var_dir'], repo)
    wrp.task = task
    wrp.job = task.current_job
    retcode = wrp.run()
    sys.exit(retcode)


def run_wrapper_if_dunder_main(dunder_name, wrapper_class, extra_classes=None):
    return run_if_dunder_main(dunder_name, run_wrapper, wrapper_class, extra_classes=extra_classes)


DEFAULT_DEVICE_ERROR_MESSAGE = "Unknown error"
DEVICE_INTERNAL_ERROR_MESSAGE = "Internal error - WMIC didn't return device status"
DEVICE_ERROR_CODES = {
    1: 'This device is not configured correctly. (Code 1)',
    3: 'The driver for this device might be corrupted, or your system may be running low on memory or other resources. (Code 3)',
    9: 'Windows cannot identify this hardware because it does not have a valid hardware identification number. (Code 9)',
    10: 'This device cannot start. (Code 10)',
    12: 'This device cannot find enough free resources that it can use. (Code 12)',
    14: 'This device cannot work properly until you restart your computer. (Code 14)',
    16: 'Windows cannot identify all the resources this device uses. (Code 16)',
    18: 'Reinstall the drivers for this device. (Code 18)',
    19: 'Windows cannot start this hardware device because its configuration information (in the registry) is incomplete or damaged. (Code 19)',
    21: 'Windows is removing this device. (Code 21)',
    22: 'This device is disabled. (Code 22)',
    24: 'This device is not present, is not working properly, or does not have all its drivers installed. (Code 24)',
    28: 'The drivers for this device are not installed. (Code 28)',
    29: 'This device is disabled because the firmware of the device did not give it the required resources. (Code 29)',
    31: 'This device is not working properly because Windows cannot load the drivers required for this device. (Code 31)',
    32: 'A driver (service) for this device has been disabled. An alternate driver may be providing this functionality. (Code 32)',
    33: 'Windows cannot determine which resources are required for this device. (Code 33)',
    34: 'Windows cannot determine the settings for this device. Consult the documentation that came with this device \
and use the Resource tab to set the configuration. (Code 34)',
    35: 'Your computer\'s system firmware does not include enough information to properly configure and use this device. \
To use this device, contact your computer manufacturer to obtain a firmware or BIOS update. (Code 35)',
    36: 'This device is requesting a PCI interrupt but is configured for an ISA interrupt (or vice versa). Please use the \
computer\'s system setup program to reconfigure the interrupt for this device. (Code 36)',
    37: 'Windows cannot initialize the device driver for this hardware. (Code 37)',
    38: 'Windows cannot load the device driver for this hardware because a previous instance of the device driver is still in memory. (Code 38)',
    39: 'Windows cannot load the device driver for this hardware. The driver may be corrupted or missing. (Code 39)',
    40: 'Windows cannot access this hardware because its service key information in the registry is missing or recorded incorrectly. (Code 40)',
    41: 'Windows successfully loaded the device driver for this hardware but cannot find the hardware device. (Code 41)',
    42: 'Windows cannot load the device driver for this hardware because there is a duplicate device already running in the system. (Code 42)',
    43: 'Windows has stopped this device because it has reported problems. (Code 43)',
    44: 'An application or service has shut down this hardware device. (Code 44)',
    45: 'Currently, this hardware device is not connected to the computer. (Code 45)',
    46: 'Windows cannot gain access to this hardware device because the operating system is in the process of shutting down. (Code 46)',
    47: 'Windows cannot use this hardware device because it has been prepared for \'safe removal\', but it has not been removed \
from the computer. (Code 47)',
    48: 'The software for this device has been blocked from starting because it is known to have problems with Windows. \
Contact the hardware vendor for a new driver. (Code 48)',
    49: 'Windows cannot start new hardware devices because the system hive is too large (exceeds the Registry Size Limit). (Code 49)',
    50: 'Windows cannot apply all of the properties for this device. Device properties may include information that describes \
the device\'s capabilities and settings (such as security settings for example). (Code 50)',
    51: 'This device is currently waiting on another device or set of devices to start. (Code 51)',
    52: 'Windows cannot verify the digital signature for the drivers required for this device. A recent hardware or software change might \
have installed a file that is signed incorrectly or damaged, or that might be malicious software from an unknown source. (Code 52)',
    -2: 'Driver not installed properly, software renderer detected.'}


def get_device_statuses(wclass='Win32_VideoController', device=''):
    """
    Returns gfx device status error code and description according to
    http://msdn.microsoft.com/en-us/library/windows/hardware/ff541422%28v=vs.85%29.aspx
    """
    where = ''
    if device:
        where = ' where \'PNPDeviceID="%s"\'' % device.replace('\\', '\\\\')
    cmd = "wmic /output:stdout /namespace:\\\\root\\cimv2 path %s%s get " % (wclass, where)
    cmd += "status, configmanagererrorcode, name, PNPDeviceID /value"
    out, _ = exec_with_timeout(cmd, 60, shell=True)
    try:
        out = bytes2string(out, encodings=('UTF16',))
    except DecodeError:
        log.debug('output length %s', len(out))
    else:
        log.debug('decoded output length %s', len(out))

    output = out.splitlines()
    statuses = []

    # group output by empty line
    devices = [list(group) for k, group in groupby(output, lambda x: x != "") if k]

    for device_desc in devices:
        code = -1
        name = ''
        dev_id = ''
        for line in device_desc:
            try:
                key, value = line.split('=', 1)
            except ValueError:
                log.debug('bad line\n%s', line)
                continue

            log.info(line)
            if key == "ConfigManagerErrorCode":
                code = int(value.strip())
                log.debug('matched error code: %s', code)
            elif key == "Status" and "unknown" in line.lower():
                code = -2
                log.debug('bad status: %s', value)
            elif key == "Name":
                name = value.strip()
                log.debug('matched name: %s', name)
            elif key == "PNPDeviceID":
                dev_id = value
                log.debug('matched device id: %s', dev_id)

        if name == "" and dev_id == '' and code == -1:
            continue

        if code == 0:
            desc = "OK"
        elif code == -1:
            code = 0
            desc = DEVICE_INTERNAL_ERROR_MESSAGE
        else:
            desc = DEVICE_ERROR_CODES.get(code, DEFAULT_DEVICE_ERROR_MESSAGE)

        statuses.append({'code': code, 'desc': desc, 'name': name, 'dev_id': dev_id})

    return statuses


def get_device_status(wclass='Win32_VideoController', device=''):
    # still need better support for more then one device
    # sorted make this deterministic
    statuses = sorted(get_device_statuses(wclass, device), key=lambda s: json.dumps(s, sort_keys=True))
    if not statuses or len(statuses) > 1:
        log.debug("Devices statuses: %s", statuses)
    if len(statuses) == 1 or device:
        status = statuses[0]
    else:
        # filter virtual devices
        hw_statuses = [s for s in statuses if "BASICRENDER" not in s['dev_id']]
        status = hw_statuses[0] if hw_statuses else statuses[0]

    del status['dev_id']
    return status


class BuildInstaller(Job):
    """ BuildInstaller is a basic driver installer.

    is_installed checks the build.txt file to determine current build.
    install calls copy_build to download the build from share to local
    directory. Find installer returns a path to a shell or INF file.
    prepare_installer modifies the commandline. Then installer is
    executed. If successful build id number is saved in build.txt.

    To write your own installer inherit from this one and make sure
    that you expose is_installed and install methods (you can override them).
    These two methods are called by Agent.
    """
    RETCODE_SUCCESS = [0]
    RETCODE_RETRY_DOWNLOAD = []
    MAX_BUILD_INST_ITERATIONS = 3

    def __init__(self, builds_dir, vardir, repo):
        self.BUILD_DEST_DIR = builds_dir
        self.VARDIR = vardir
        self.repo = repo
        self.job = {}
        self.task_system = None
        self.task_config = None

    def _run_config_vectors(self, base_name):
        vector_names = utils.filter_names_not_bad_endings(self.task.config, base_name)
        vector_names.sort()
        for vector_name in vector_names:
            self.run_config_cmd(self.VARDIR, vector_name, self.task, self.VARDIR)

    def run(self):
        """ It is possible to use more than one config_pre_install and config_post_install vectors. They have to
        have unique names and contains 'config_pre_install' or 'config_post_install' strings."""

        # check if component is installed
        return_dict = self.is_installed(self.task, self.job['build_id_file'])

        # if not and new os is required then install new one
        if return_dict.get('new_os', False):
            self.install_new_os()

        if return_dict['installed']:
            # if component is installed then go to next component
            return_dict['reboot'] = False
            return_dict['successful'] = True
        elif return_dict.get('error', None):
            # if component is not installed and the check erred then skip installation and report error
            return_dict['successful'] = False
        else:
            # component is not installed so install it
            try:
                # TODO: self.send_alive(AGENT_INSTALLING_BUILD)
                # run config pre install scripts
                self._run_config_vectors('config_pre_install')

                # !!! DO THE INSTALLATION !!!
                result = self.install(self.task, self.job['build_id_file'])
                return_dict.update(result)

                self._run_config_vectors('config_post_install')
            except RebootNeededError:
                self._run_config_vectors('config_post_install')
                self.reboot()
            except ShutdownNeededError:
                return_dict['reboot'] = True
                return_dict['hard_reboot'] = True
            except:
                log.exception("Build installation failed")
                return_dict.update({'successful': False, 'error': traceback.format_exc()})

        if return_dict.get('reboot', False):
            self.exit(**return_dict)
        return_dict.update(self.finalize())
        self.exit(**return_dict)

    def copy_test_dir(self):
        return

    def finalize(self):
        return {}

    def _is_reload_os_needed(self, task, build_id_file):
        return os.path.exists(build_id_file) and string_bool(task.config.get('reload_os', ""))

    def _set_build_install_iteration(self, iteration, iteration_file, installer_name, task):
        txt = 'build_install_iteration_task_' + str(task) + '_' + installer_name + ': ' + str(iteration) + '\n'
        utils.fappend(iteration_file, txt)

    def _get_current_build_install_iteration(self, filepath, installer_name, task_id):
        """ Gets install iteration written to build_install.txt."""
        if not os.path.exists(filepath):
            return 0

        iteration = 0
        pattern = 'build_install_iteration_task_{0}_{1}:\s(\d+)'.format(task_id, installer_name)
        regex = re.compile(pattern)
        for line in utils.fread_by_line(filepath):
            m = regex.search(line)
            if m:
                iteration = m.group(1)
                log.info("Iteration for %s task-%s has been found: %s", installer_name, task_id, iteration)

        return int(iteration)

    def _install_iteration_allowed(self, task):

        build_inst_file = join(self.VARDIR, "build_install.txt")
        installer_name = self.__class__.__name__

        iteration = self._get_current_build_install_iteration(build_inst_file, installer_name, task.get_id())
        log.info("Number of %s build installation iterations: %s", installer_name, iteration)

        if iteration >= self.MAX_BUILD_INST_ITERATIONS:
            log.error("Number of %s build installation iterations exceeded. Os reload needed.", installer_name)
            return False

        iteration += 1
        log.info("Setting %s build iteration to: %s", installer_name, iteration)
        self._set_build_install_iteration(iteration, build_inst_file, installer_name, task.get_id())

        return True

    def is_installed(self, task, build_id_file):
        """
        Standard installation check based on build_id.txt.

        This method must check if CORRECT VERSION of build is installed.
        Overload this in child classes if better check is required.
        The check is based on build ID and build scenario.
        """

        # get current build id and path
        build_id = get_current_build_id(build_id_file)
        scenario = get_current_scenario(build_id_file)
        build_type = get_current_build_type(build_id_file)

        bld_path, _, _ = self._get_build_dest_path(task.current_job)

        log.info("Currently installed build: %s scenario: %s build_type: %s", build_id, scenario, build_type)
        # check if build id is as expected
        if build_id != task.current_job['build_id']:
            log.info("Currently installed build is %s while expected is %s", build_id, task.current_job['build_id'])
            return {'installed': False, 'local_build_dest_dir': bld_path, 'msg': 'build id mismatch'}
        if scenario and scenario != task.current_job['scenario']:
            log.info("Currently installed build (%s) was installed with scenario: %s when expected: %s",
                     build_id, scenario, task.current_job['scenario'])
            return {'installed': False, 'local_build_dest_dir': bld_path, 'msg': 'scenario mismatch'}

        # check local path to the build
        if not os.path.exists(bld_path):
            log.info("Required build %d is missing, expected in %s", build_id, bld_path)
            return {'installed': False, 'local_build_dest_dir': bld_path}

        required_build_type = self._get_task_build_type(task)
        if required_build_type != build_type:
            log.info("Required build type: %s, installed build type: %s.", required_build_type, build_type)
            return {'installed': False, 'local_build_dest_dir': bld_path}

        log.info("Expected build (%d) is currently installed", build_id)
        return {'installed': True, 'local_build_dest_dir': bld_path}

    def _get_task_build_type(self, task):
        return "coverage" if self.is_coverage_build(task) else "-1"

    def _prepare_installer_cmd(self, cmd):
        return cmd, '.'

    def is_coverage_build(self, task=None):
        if task is None:
            task = self.task
        return string_bool(task.config.get('coverage', ''))

    def run_config_cmd(self, bld_path, config_name, task, cwd):
        if checks.is_linux() or checks.is_macos():
            config_batch_file = utils.join(bld_path, "/%s.sh" % config_name)
        else:
            config_batch_file = utils.join(bld_path, "/%s.bat" % config_name)

        # create config_batch_file
        try:
            config_data = task.config[config_name]
        except KeyError:
            log.info("No %s in vector, using %s (if available).", config_name, config_batch_file)
        else:
            log.info("Creating batch file %s from %s vector.", config_batch_file, config_name)
            if os.path.exists(config_batch_file):
                log.warning("Overwriting existing %s.", config_batch_file)
            with open(config_batch_file, "w") as f:
                f.write(str(config_data))  # TODO: convert to utils.fwrite
            os.chmod(config_batch_file, 0o755)

        if os.path.exists(config_batch_file):
            with open(config_batch_file, "r") as f:
                tmp = f.read()  # TODO: convert to utils.fread
            log.info("Applying %s:\n%s", config_name, tmp)

            txt, retcode = exec_with_timeout(config_batch_file, 300, shell=True, tracing=True, cwd=cwd)
            log.info("%s exit code %s, output:\n%s", config_name, retcode, txt)

            # Errors from configuration scripts shouldn't be silenced by Berta.
            # If errors during script execution are acceptable, users should handle them
            # consciously inside the script.
            if retcode:
                raise Exception("Problem during build configuration!")

            if "TriggerHardwareReboot" in txt:
                raise utils.ShutdownNeededError("Buildinstaller triggered hardware reboot")

            if "TriggerSoftwareReboot" in txt:
                raise utils.RebootNeededError("Buildinstaller triggered software reboot")

    def _install(self, local_bld_path):
        job = self.task.current_job

        installer_cmd = self._find_installer(local_bld_path)
        if not installer_cmd:
            return {'successful': False, 'error': "Cannot find installer"}

        installer_cmd, installer_dir = self._prepare_installer_cmd(installer_cmd)
        if not installer_cmd:
            return {'successful': False, 'error': "Preparing installer failed.", 'installer_dir': installer_dir}

        # Check installer build iteration
        if not self._install_iteration_allowed(self.task):
            return {'new_os': True, 'installer_dir': installer_dir}

        txt, retcode = '', -1
        for retries in range(2, 0, -1):
            # run build installer, timeout = 1000 seconds
            txt, retcode = exec_with_timeout(installer_cmd, 1000, shell=True, tracing=True,
                                             cwd=installer_dir, universal_newlines=True)
            log.info("Installer output: %s", txt)
            if retcode not in self.RETCODE_RETRY_DOWNLOAD:
                break

            # probably there was something wrong with file system while proxyAgent pushed build to vm disc
            # give it one more chance to install correctly by pulling build directly from samba
            log.warning("%s FAILED, retcode %d, retries left %d" % (installer_cmd, retcode, retries))
            self._copy_build(job)

        if retcode not in self.RETCODE_SUCCESS:
            log.warning("%s FAILED, retcode %d", installer_cmd, retcode)
            return {'successful': False, 'error': txt, 'retcode': retcode, 'installer_dir': installer_dir}

        log.info("%s succeed, retcode %d", installer_cmd, retcode)
        return {'successful': True, 'installer_dir': installer_dir}

    def install(self, task, build_id_file):
        job = task.current_job
        log.info("Installing required build: %d", job['build_id'])

        self.task_system = task.get_system_job()['system']
        self.task_config = task.config

        local_bld_path = self._copy_build(job)
        if not local_bld_path:
            log.warning("Cannot copy build")
            return {'successful': False, 'error': "Cannot copy build"}
        log.info("Build copied to %s", local_bld_path)

        result = self._install(local_bld_path)
        if not result.get('successful', False):
            return result

        build_id = job['build_id']
        self._set_build_id(build_id, build_id_file)

        self.run_config_cmd(local_bld_path, 'build_customization', task, result.get('installer_dir', '.'))

        self._post_install_action()

        ok_result = {'successful': True, 'reboot': True, 'local_build_dest_dir': local_bld_path}
        ok_result.update(result)
        return ok_result

    def _set_build_id(self, build_id, build_id_file):
        """
        Write information about the state of the installation of
        the build into a file.  The first line of the file is
        the ID of the build as known within Berta.  The next line
        of the file is the scenario of the installation, if there
        is a scenario for the installation.  Then a line for whether
        the build is a coverage build, where -1 means a non-coverage
        installation.

        :param build_id: The ID of the build installed
        :param build_id_file: The path of the file
        :raises Exception If the file cannot be written
        """
        str_buffer = StringIO()
        str_buffer.write('build_id: ')
        str_buffer.write(str(build_id))
        str_buffer.write('\n')

        try:
            scenario = self.task.current_job['scenario']
        except KeyError:
            pass
        else:
            str_buffer.write('scenario: ')
            str_buffer.write(str(scenario))
            str_buffer.write('\n')

        try:
            build_comment = self.task.current_job['build_comment']
        except KeyError:
            pass
        else:
            str_buffer.write('build_comment: ')
            str_buffer.write(str(build_comment))
            str_buffer.write('\n')

        try:
            configured_build_target = getattr(self, 'configured_build_target')
        except AttributeError:
            pass
        else:
            log.info('Writing %s to %s', configured_build_target, build_id_file)
            str_buffer.write('build_target_version: ')
            str_buffer.write(str(configured_build_target))
            str_buffer.write('\n')

        str_buffer.write('build_type: ')
        str_buffer.write(self._get_task_build_type(self.task))
        str_buffer.write('\n')

        str_buffer.write('tool_id: ')
        tool_id = get_tool_id_from_path(self.task)

        # To find out if tool has a build (then last path element has pattern: ToolID_ToolBuildID)
        if len(tool_id.split('_')) > 1:
            str_buffer.write(str(tool_id))
        else:
            str_buffer.write('-1')
        str_buffer.write('\n')

        try:
            with open(build_id_file, 'w') as handle:
                handle.write(str_buffer.getvalue())  # TODO: convert to utils.fwrite
                handle.flush()
                os.fsync(handle)
        except:
            log.exception('Could not write to file %s.', build_id_file)
            raise

        try:
            with open(build_id_file, 'r') as handle:
                content_file = handle.read()  # TODO: convert to utils.fread
            log.debug('File %s content: %s.', build_id_file, content_file)
        except:
            log.exception('Could not read file %s.', build_id_file)

    def store_build_metadata(self):
        build_id = self.task.current_job["build_id"]
        build_id_file = self.job['build_id_file']
        self._set_build_id(build_id, build_id_file)

    def _post_install_action(self):
        return {}

    def _get_build_dest_path(self, job, bld_path=None, bld_name=None):
        if bld_path is None:
            bld_path = self.repo.get_build_dir(job)
        if bld_name is None:
            bld_name = os.path.basename(bld_path)

        # os.path.basename is different from unix basename
        # it returns '' from '/foo/bar/' instead of 'bar'
        dest = join(self.BUILD_DEST_DIR, bld_name)
        return dest, bld_path, bld_name

    def _copy_build(self, job, path=None, bld_path=None, bld_name=None):
        # self.send_alive(AGENT_COPYING_BUILD)
        dest, bld_path, bld_name = self._get_build_dest_path(job, bld_path, bld_name)
        log.info("Build path: %s, build name: %s, destination: %s", bld_path, bld_name, dest)

        # try for three times to copy the build
        for copy_attempt in range(1, 4):
            log.info("copying build (try %s) to %s", copy_attempt, dest)

            try:
                local_bld_path = self._copy_build_part(job, bld_path, dest, path)
                return local_bld_path
            except NotImplementedError:
                raise
            except:
                log.info("Build is already exists, deleted and re-copy it")
                if os.path.exists(dest):
                    utils.rm_tree(dest)

        return False

    def _copy_build_part(self, job, build_path, dest, path=None):
        if path:
            build_path = os.path.join(build_path, path)
            dest = os.path.join(dest, path)
        log.info("Copying build from %s to %s." % (build_path, dest))

        if job['is_buildstore']:
            if job['buildstore_type'] == consts.BUILDSTORE_TYPE_HTTP:
                self._get_build_from_http(build_path, dest)
            elif job['buildstore_type'] in [consts.BUILDSTORE_TYPE_SHARE, consts.BUILDSTORE_TYPE_RESOURCE]:
                build_path = self.repo.get_build_dir(job)
                log.debug("build_path 1: %s", build_path)
                if path:
                    build_path = os.path.join(build_path, path)
                    log.debug("build_path 2: %s", build_path)
                self._get_build_from_internal_share(build_path, dest)
            elif job['buildstore_type'] == consts.BUILDSTORE_TYPE_ARTIFACTORY:
                build_path = self.job['build_path']
                if path:
                    build_path = os.path.join(build_path, path)
                log.debug("build_path: %s", build_path)
                self._get_build_from_artifactory(build_path, dest)
            else:
                raise NotImplementedError("missing implementation for buildstore type %s" % job['buildstore_type'])
        else:
            self._get_build_from_internal_share(build_path, dest)

        return dest

    def _get_build_from_http(self, build_path, dest):
        if not build_path.endswith("/"):
            build_path += "/"

        httphelper.http_copy_files(build_path, dest)

    def _get_build_from_internal_share(self, build_path, dest):
        shutil.copytree(build_path, dest)

    def _get_build_from_artifactory(self, build_path, dest):
        repo = repository.get_repo(self.VARDIR, store_type=consts.BUILDSTORE_TYPE_ARTIFACTORY)
        repo.setup(self.job['buildstore_path'], self.job['buildstore_username'], self.job['buildstore_password'])
        repo.copy_dir(build_path, dest)

    def _find_installer(self, bld_path):
        # find installer, this is simple, extend in child classes
        path = join(bld_path, "installer")
        if os.path.exists(path):
            return path
        else:
            return False

    def _get_configured_build_target(self, task, default=None):
        build_target_version = task.config.get('build_target_version', default)
        if build_target_version:
            build_target_version = build_target_version.strip()
            log.info('Selected of target to installation: %s', build_target_version)
        return build_target_version

    def get_info(self, prod_info):
        """Abtract method, extend in child classes.
        In child class implementations, add dictionary elements to prod_info
        (but be careful to use unique keys if your product uses multiple installers).
        """
        pass

    def _get_ahk_interpreter(self, expected=None):
        sys_drive = os.environ.get("SYSTEMDRIVE", "C:")
        system_str = checks.get_system()
        log.info('got system string %s', system_str)
        if expected and system_str != expected:
            system_str = expected
        if "64" in system_str:
            arch = ' (x86)'
        else:
            arch = ''
        return "%s\\program files%s\\autohotkey\\autohotkey.exe" % (sys_drive, arch)


class WindowsInstaller(BuildInstaller):
    """ Windows driver installer """

    # devcon error codes:
    #0     Success
    #1     Requires reboot
    #2     Failure
    #3     Syntax error
    RETCODE_SUCCESS = [0, 1]
    MAX_BUILD_INST_ITERATIONS = 1

    def __init__(self, builds_dir, vardir, repo):
        super(WindowsInstaller, self).__init__(builds_dir, vardir, repo)
        self.BUILD_REGISTRY_FILE = join(self.VARDIR, "bld_registry.bak")
        self.search_mask = ".inf"

    def search_dir(self, dir_path):
        """
        Searches for provided mask (default: INF file) in dir_path.
        Returns a tuple (count, path) where count is number of items,
        that match mask (default: inf files) found in dir_path
        and path is first item's (default: inf) NAME.
        """
        if not os.path.exists(dir_path) or not os.path.isdir(dir_path):
            log.debug("Search dir: %s doesn't exist", dir_path)
            return 0, None

        installers = [f for f in os.listdir(dir_path) if f.endswith(self.search_mask)]
        return len(installers), installers[0]

    def search_multiple_dirs(self, base_path, subdirs):
        """Returns first found installer.

        E.g. base_path=base/dir/
        subdirs=[['a', 'b'], ['c']]

        will return

        1, c/file.inf

        if file.inf is found in subdir c but not a/b."""

        infs_count = 0
        installer = None
        for subdir in subdirs:
            path = join(base_path, *subdir)
            infs_count, installer = self.search_dir(path)
            if installer:
                log.info("Found installer: %s @ search dir: %s.", installer, path)
                return infs_count, join(join(*subdir), installer)

        return infs_count, installer

    def multiply_dirs(self, subdir):
        """Make a list of the format [subdir, subdir[1:], subdir[2:]...] from [subdir]."""
        multiply = []
        for directory in subdir:
            for x in range(len(directory)):
                if not directory[x:] in multiply:
                    multiply.append(directory[x:])

        return multiply if multiply else ""

    def system_subdir(self):
        """ Get the unified build directories. """
        system = self.task_system
        if "Windows-5" in system and "-32" in system:
            subdir = [("GFXDriver", "Release", "xp32"),
                      ("GFXDriver", "Release-Internal", "xp32"),
                      ("GFXDriver", "Debug", "xp32"),
                      ("Installer", "Graphics"),
                      ("",)]
        elif "Windows-5" in system and "-64" in system:
            subdir = [("GFXDriver64", "Release", "xp64"),
                      ("GFXDriver64", "Release-Internal", "xp64"),
                      ("GFXDriver64", "Debug", "xp64"),
                      ("Installer64", "Graphics"),
                      ("",)]
        elif "Windows-6" in system and "-32" in system:
            subdir = [("GFXVista32", "Release", "lh32"),
                      ("GFXVista32", "Release-Internal", "lh32"),
                      ("GFXVista32", "Debug", "lh32"),
                      ("InstallerVista32", "Graphics"),
                      ("",)]
        elif "Windows-6" in system and "-64" in system:
            subdir = [("GFXVista64", "Release", "lh64"),
                      ("GFXVista64", "Release-Internal", "lh64"),
                      ("GFXVista64", "Debug", "lh64"),
                      ("InstallerVista64", "Graphics"),
                      ("",)]
        else:
            subdir = None

        return self.multiply_dirs(subdir) if subdir else []

    def _find_installer(self, bld_path):
        """ Gets first INF file in bld_path """

        # look for unified build
        system_subdir = self.system_subdir()
        infs_count, installer = self.search_multiple_dirs(bld_path, system_subdir)

        if not installer:
            log.warning("Installer not found in any of %s.", system_subdir)
            return False

        if infs_count == 0 or not installer:
            log.warning("Cannot find installer")
            return False

        elif infs_count > 1:
            log.warning("More than one %s in driver_path", self.search_mask)

        installer_path = join(bld_path, installer)
        log.info("Found installer: %s", installer_path)
        return installer_path

    def _enable_callstack(self, task):
        log.info("Enabling call stack dump in registry")

        # find PDB directory
        bld_path = task.current_job['build_path']
        bld_path = self._find_installer(join(self.BUILD_DEST_DIR, os.path.basename(bld_path)))
        if not bld_path:
            log.warning("Cannot find INF directory to select PDBs for call stack dump.")
            return
        bld_path = os.path.dirname(bld_path)
        pdb_dir = join(bld_path, "pdb")
        if not os.path.exists(pdb_dir):
            log.info("Cannot find PDB directory in %s. Call stack dumps disabled." % pdb_dir)
            return

        # choose correct REG file
        util_dir = join(os.environ["PYTHONPATH"].split(os.pathsep)[0], "utils")
        if self.task_system.endswith("-32"):
            reg_name = join(util_dir, "callstack_dumper_32.reg")
        else:
            reg_name = join(util_dir, "callstack_dumper_64.reg")

        # patch REG file with PDB, LOG and dumper locations
        reg_data = utils.fread(reg_name)

        new_dumper_path = join(util_dir, "callstack_dumper.exe").replace("\\", "\\\\")
        reg_data = reg_data.replace("k:\\\\callstack_dumper.exe", new_dumper_path)

        new_dumper64_path = join(util_dir, "callstack_dumper64.exe").replace("\\", "\\\\")
        reg_data = reg_data.replace("k:\\\\callstack_dumper64.exe", new_dumper64_path)

        new_log_path = join(self.VARDIR, "crash.txt").replace("\\", "\\\\")
        reg_data = reg_data.replace("k:\\\\log.txt", new_log_path)

        minidump_path = join(self.VARDIR, "minidump.txt").replace("\\", "\\\\")
        reg_data = reg_data.replace(" -log-file", " -minidump %s -log-file" % minidump_path)

        new_pdb_path = "-pdb-path %s" % pdb_dir.replace("\\", "\\\\")
        log.debug(new_pdb_path)
        reg_data = reg_data.replace("-pdb-path k:\\\\", new_pdb_path)

        with open(reg_name, 'w') as handle:
            handle.write(reg_data)  # TODO: convert to utils.fwrite
        exec_with_timeout("regedit.exe /s %s" % reg_name, 10, shell=True, tracing=True)

    def install(self, task, build_id_file):
        # registry backup must be done before any reg modification done by the installer
        utils.registry_backup(self.BUILD_REGISTRY_FILE)

        result = super(WindowsInstaller, self).install(task, build_id_file)
        if result.get('successful', False):
            self._enable_callstack(task)
        return result

    def is_installed(self, task, build_id_file):
        if not super(WindowsInstaller, self).is_installed(task, build_id_file)['installed']:
            return {'installed': False}

        self.task_system = task['system']

        build_id = get_current_build_id(build_id_file)
        if build_id == task['build_id']:
            device_status = self._get_device_status()
            log.info("Gfx device status - code and description: %s, %s", device_status['code'], device_status['desc'])
            if device_status['code'] == 0:
                log.info("Required build is installed: %s", task['build_id'])
                return {'installed': True}
            else:
                return {'installed': False, 'error': device_status['desc']}

        log.info("Current build: %d" % build_id)
        return {'installed': False}

    def _get_device_status(self, wclass='Win32_VideoController', device=''):
        return get_device_status(wclass, device)

    def _match_inf_os(self, mfg, win7_is_vista=True):
        """
        This selects manufacturer string according to
        INF Manufacturer Section from MSDN
        http://msdn.microsoft.com/en-us/library/ff547454(VS.85).aspx

        nt[Architecture][.[OSMajorVersion][.[OSMinorVersion][.[ProductType][.SuiteMask]]]]

        """
        common = mfg[0].strip()  # Intel.Mfg
        for os_arch in mfg[1:]:
            arch = os_arch.split('.')[0].strip()

            # check architecture
            is_ia = "-64ia" in self.task_system
            if arch.lower() == 'nt':
                pass
            elif is_ia and "ia64" in arch.lower():
                pass
            elif not is_ia and "-64" in self.task_system and "amd64" in arch.lower():
                pass
            elif "-32" in self.task_system and "86" in arch:
                pass
            else:
                continue

            # check os
            rest = os_arch.split('.', 1)
            try:
                op_sys = rest[1][0:3]  # 6.0.something...0x80
            except IndexError:
                pass
            else:
                curr_sys = self.task_system[8:11]  # Windows-6.1-xxxx-32
                if curr_sys == op_sys:
                    pass
                elif win7_is_vista and curr_sys == '6.1' and op_sys == '6.0':  # map Win7 to Vista
                    pass
                elif op_sys.startswith('..'):  # no OS but some other parts
                    pass
                elif (op_sys.endswith('..') or len(op_sys) < 3) and op_sys[0] == curr_sys[0]:
                    pass  # only major
                else:
                    continue

            return utils.str_join('.', common, os_arch.strip())
        return None

    def _check_supported_hw(self, inf_file, mfg):
        if not os.path.exists(inf_file):
            log.info("Not found inf file.")
            return None
        supported_hw = []
        mfg_tag = '[{0}]'.format(mfg)
        within = False
        for line in utils.fread_by_line(inf_file):
            if line == '':
                break
            if line.startswith(mfg_tag):
                within = True
                continue
            if within and line.startswith('['):
                break
            if line.startswith('%') or line.startswith('"'):
                hw_id = line.split('=')[1].split(',')[1].strip()
                supported_hw.append(hw_id)
        return supported_hw

    def _prepare_installer_cmd(self, inf_file):
        """
        _prepare_installer_cmd checks available devices in Device Manager
        (devcon) and matches them with devices listed in inf_file.
        It returns devcon.exe command_line for found matching device.

        inf_file is an *.inf device description file
        prepare_installer wraps *.inf in devcon.exe update command
        """

        inf = configparser.ConfigParser()
        try:
            inf.read(inf_file)
        except configparser.ParsingError:
            # INF syntax does not match exactly ConfigParser but it works
            # to some degree; if in the future it starts failing then drop
            # ConfigParser
            # and implement custom parsing of INF file
            log.exception("IGNORED EXCEPTION")

        try:
            mfg = inf.get("Manufacturer", "%Intel%")
            mfg = str(mfg).split(",")
        except:
            log.info("Manufacturer: Intel not found, looking for KMDName manufacturer.")
            try:
                mfg = inf.get("Manufacturer", "%KMDName%")
                mfg = str(mfg).split(",")
            except:
                log.exception("WRONG MANUFACTURER")
                return False, '.'

        supported_hw = ""
        if len(mfg) == 1:
            mfg = mfg[0]
            supported_hw = self._check_supported_hw(inf_file, mfg)
        elif len(mfg) == 2:
            mfg[1] = mfg[0].strip() + "." + mfg[1].strip()
            for poss_mfg in mfg:
                supported_hw = self._check_supported_hw(inf_file, poss_mfg)
                if supported_hw:
                    break
        elif len(mfg) > 2:
            # INF decorated for the OS Version and Architecture
            mfg = self._match_inf_os(mfg)
            if not mfg:
                raise Exception("cannot recognize mfg")
            supported_hw = self._check_supported_hw(inf_file, mfg)
        else:
            raise Exception("cannot recognize mfg")
        log.info(mfg)

        # find matching devices to INFO
        cmd = "devcon.exe hwids *"
        txt, retcode = exec_with_timeout(cmd, 180, shell=True)  # 180 seconds, devcon is slow
        if retcode != 0 or len(txt) < 300:
            log.error("%s FAILED, retcode %d", cmd, retcode)
            return False, '.'
        devices = []
        fragment = ''
        for l in txt.split("\n"):
            if re.match("^[A-Za-z].*", l):
                fragment = None
                dev = {"name": l.strip(), "ids": [], "caption": []}
                devices.append(dev)
                continue
            if re.match(".*Name:.*", l):
                m = re.search("Name: (.*)", l)
                dev['caption'].append(m.group(1))
                continue
            if re.match(".*Hardware ID.*", l):
                fragment = "HWids"
                continue
            if re.match(".*Compatible ID.*", l):
                fragment = "CMPTids"
                continue
            if fragment == "HWids":
                dev["ids"].append(l.strip())

        devices2 = []

        for d in devices:
            for hw in supported_hw:
                if hw in d["ids"] and "CPU" not in d["caption"][0]:
                    devices2.append(d)
        if not devices2:  # for backward capability
            for d in devices:
                for hw in supported_hw:
                    if d["name"].startswith(hw) and "CPU" not in d["caption"][0]:
                        devices2.append(d)

        devices = devices2

        if not devices:
            log.error("No matching device to driver found")
            return False, '.'
        elif len(devices) > 1:
            log.warning("more than one matching device to driver found")

        log.info("matching devices: %s", [d["name"] for d in devices])

        # if there is any previously installed driver package then delete it
        for dev in devices:
            cmd = "devcon.exe drivernodes %s" % dev["ids"][0]
            txt, retcode = exec_with_timeout(cmd, 120)  # 120 seconds
            txt_lines = txt.split("\n")
            if retcode != 0 or len(txt_lines) < 3:
                log.error("%s FAILED, retcode %d", cmd, retcode)
                return False, '.'

            cmd = "devcon.exe -f dp_delete"
            for l in txt_lines:
                m = re.search("Inf file is (.*)", l)
                if not m:
                    continue
                log.info("line: %s", l)
                inf = m.group(1)
                cmd2 = "%s %s" % (cmd, inf)
                retcode = os.system(cmd2)
                if retcode != 0:
                    log.warning("%s failed, retcode %d", cmd2, retcode)
                else:
                    log.info("%s succeed, retcode %d", cmd2, retcode)

        # start AHK script for clicking dialogs from devcon
        os.spawnl(os.P_NOWAIT, self._get_ahk_interpreter(), "autohotkey.exe c:\\berta\\drvinst.ahk")

        cmd = 'devcon.exe update %s "%s"' % (inf_file, devices[0]["ids"][0])
        return cmd, '.'

    def get_info(self, prod_info):
        prod_info["sku"] = checks.get_sku()


def get_tool_id_from_path(task):
    """ Gets tool id with tool build id from tool_path """
    try:
        tool_id = os.path.split((task.get_test_job()['tool_path']))[-1]
    except:
        tool_id = ''
    return tool_id


def get_current_tool_id(filepath):
    """ Gets tool id written to BUILD_ID_FILE. Tool id should be unique. """
    return _get_current_field(filepath, 'tool_id', -1)


def get_current_build_id(filepath):
    """ Gets build id written to BUILD_ID_FILE. Build id should be unique. """
    return int(_get_current_field(filepath, 'build_id', -1))


def get_current_build_type(filepath):
    """ Gets build type written to BUILD_ID_FILE. """
    return _get_current_field(filepath, 'build_type', -1)


def get_current_build_comment(filepath):
    """ Gets build comment written to BUILD_ID_FILE. """
    return _get_current_field(filepath, 'build_comment', -1)


def get_current_scenario(filepath):
    """ Gets scenario id written to BUILD_ID_FILE."""
    return _get_current_field(filepath, 'scenario')


def get_current_build_target_version(filepath, default=None):
    """ Gets build target version written to BUILD_ID_FILE."""
    return _get_current_field(filepath, 'build_target_version', default)


def _get_current_field(filepath, field_name, default=None):
    """ Gets field written to BUILD_ID_FILE."""
    if not os.path.exists(filepath):
        # No error, because after OS reload file is always missing
        log.debug('File %s does not exists.', filepath)
        return default
    try:
        txt = utils.freadlines(filepath)
    except:
        log.exception("IGNORE EXCEPTION")
        return default

    for line in txt:
        m = re.search("%s:\s+(\S+)" % field_name, line)
        if m:
            return m.group(1)

    log.debug('Could not read field %s from file %s. Return default %s.', field_name, filepath, default)
    return default


def finalize_build_install(build_inst_file):
    """Clear build install iteration logs and print summary"""
    if os.path.exists(build_inst_file):
        with open(build_inst_file, 'r') as handle:
            install_txt = handle.read()  # TODO: convert to utils.fread
        log.info("Build installation summary: \n%s", install_txt)
        os.remove(build_inst_file)
    else:
        log.info("Build installation summary file is not present: %s", build_inst_file)
