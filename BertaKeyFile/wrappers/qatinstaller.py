import logging
import os
import os.path
import shutil
import time
import utils

from wrappers.buildinstallers import BuildInstaller, run_wrapper, get_current_build_comment
from distutils.dir_util import copy_tree
from utils import exec_with_timeout

log = logging.getLogger(__name__)


class QatInstaller(BuildInstaller):

    # TODO: Janky workaround for expediency, fix by calling buildinstallers.py helper functions to derive this
    QATBUILD_ROOT = "Z:\\"

    # QatTestTools
    QATTEST_SRC = "T:\\QatTestBerta"
    QATTEST_DST = "C:\\QatTestBerta"
    QATTEST_REBOOTFILE = "C:\\berta\\var\\reboot.txt"

    # MS Shared Repo Special build
    MS_REPO = "MS-QAT"
    MS_REPO_BUILD_FILE = "qatbuild.txt"

    # PFVF Special builds
    PFVF_HEADER = "PFVF_"
    PF_VF_BUILD_FILE = "pfvf_build.txt"

    def __init__(self, builds_dir, vardir, repo):
        BuildInstaller.__init__(self, builds_dir, vardir, repo)
        self.pspath = self.get_ps_binary()

    def run(self):
        log.info("QatInstaller.run")

        """
        General flow (assumption is os is ALWAYS reloaded). Proceed with caution if dev testing without os reload.
        1. Copy driver to SUT and install driver build
        2. Run your tests
        3. No cleanup (because we're going to os reload anyways)
        """
        super(QatInstaller, self).run()

    def is_installed(self, task, build_id_file):
        return {'successful': False, 'installed': False, 'reboot': False}

    def install(self, task, build_id_file):
        # Return values here get rolled up and updated to BuildInstaller.run
        job = task.current_job
        log.info("QatInstaller.install: initialized")

        self.copy_test_dir()

        # Initialize all this to false
        hyperv_mode = "false"
        test_mode = "false"
        debug_mode = "false"
        UQ_mode = "false"
        driver_verifier = "false"
        rebootFlag = False
        UninstallFlag = False

        build_comment = get_current_build_comment(build_id_file)
        uninstalldriverpath = os.path.join(job['build_dest_dir'], build_comment)
        log.info('uninstall driver path: {}'.format(uninstalldriverpath))

        installdriverpath = os.path.join(job['build_dest_dir'], job['build_comment'])
        log.info('install driver path: {}'.format(installdriverpath))

        # get flag: HV mode
        if task.config.get("hyperv_mode", "false").lower() in ("yes", "true", "t", "1"):
            hyperv_mode = "true"

        # get flag: Test mode
        if task.config.get("test_mode", "false").lower() in ("yes", "true", "t", "1"):
            test_mode = "true"

        # get flag: Debug mode
        if task.config.get("debug_mode", "false").lower() in ("yes", "true", "t", "1"):
            debug_mode = "true"

        # get flag: UQ mode
        if task.config.get("UQ_mode", "false").lower() in ("yes", "true", "t", "1"):
            UQ_mode = "true"

        # get flag: driver verifier
        if task.config.get("driver_verifier", "false").lower() in ("yes", "true", "t", "1"):
            driver_verifier = "true"

        # Update QatTestBerta files and PS proFile
        log.info('-'*80)
        log.info('Update QatTestBerta files and PS proFile')

        command = r"""Berta-ENVInit"""
        _, _ = self.invoke_pscommand(self.pspath, command, 240, shell=False)

        # check main files of berta
        log.info('-'*80)
        log.info('update main files of berta')

        command = r"""Berta-UpdateMainFiles"""
        out, rc = self.invoke_pscommand(self.pspath, command, 240, shell=False)
        out = self.convert_ps_return(out, 'bool')

        if rc == 0:
            if out:
                rebootFlag = True
                log.info('check berta: need update main files')
            else:
                log.info('check berta: not need update main files')

        # check test ENV
        # check: Test mode
        log.info('-'*80)
        log.info('check test ENV: Test mode')

        command = r"""UT-CheckTestMode -CheckFlag ${0} -Remote $false""".format(test_mode)
        out, rc = self.invoke_pscommand(self.pspath, command, 240, shell=False)
        out = self.convert_ps_return(out, 'bool')

        if rc == 0:
            if out:
                log.info('check test ENV: not need change test mode')
            else:
                log.info('check test ENV: need change test mode')

                command = r"""UT-SetTestMode -TestMode ${0} -Remote $false""".format(test_mode)
                out, rc = self.invoke_pscommand(self.pspath, command, 240, shell=False)
                rebootFlag = True

        # check: Debug mode
        log.info('-'*80)
        log.info('check test ENV: Debug mode')

        command = r"""UT-CheckDebugMode -CheckFlag ${0} -Remote $false""".format(debug_mode)
        out, rc = self.invoke_pscommand(self.pspath, command, 240, shell=False)
        out = self.convert_ps_return(out, 'bool')

        if rc == 0:
            if out:
                log.info('check test ENV: not need change debug mode')
            else:
                log.info('check test ENV: need change debug mode')

                command = r"""UT-SetDebugMode -DebugMode ${0} -Remote $false""".format(debug_mode)
                out, rc = self.invoke_pscommand(self.pspath, command, 240, shell=False)
                rebootFlag = True

        # check: driver verifier
        log.info('-'*80)
        log.info('check test ENV: Driver verifier')

        command = r"""UT-CheckDriverVerifier -CheckFlag ${0} -Remote $false""".format(driver_verifier)
        out, rc = self.invoke_pscommand(self.pspath, command, 240, shell=False)
        out = self.convert_ps_return(out, 'bool')

        if rc == 0:
            if out:
                log.info('check test ENV: not need change driver verifier')
            else:
                log.info('check test ENV: need change driver verifier')

                command = r"""UT-SetDriverVerifier -DriverVerifier ${0} -Remote $false""".format(driver_verifier)
                out, rc = self.invoke_pscommand(self.pspath, command, 240, shell=False)
                rebootFlag = True

        # check reboot
        if rebootFlag:
            log.info('QatInstaller.install: system reboot is required for the changes to take effect')
            return {'successful': True, 'installed': False, 'reboot': True}

        # check: qat driver installed
        log.info('-'*80)
        log.info('check test ENV: QAT driver')

        out = self._is_winqat_installed()
        if out:
            log.info('check test ENV: QAT driver is installed')

            return_dict = super(QatInstaller, self).is_installed(task, build_id_file)
            if return_dict['installed']:
                # check: HV mode
                log.info('check test ENV: HV mode')
                command = r"""WBase-CheckDriverHVMode -CheckFlag ${0}""".format(hyperv_mode)
                out, rc = self.invoke_pscommand(self.pspath, command, 240, shell=False)
                out = self.convert_ps_return(out, 'bool')

                if out:
                    log.info('check test ENV: not need change HV mode')
                    pass
                    return_dict['reboot'] = False
                    return_dict['successful'] = True
                    return return_dict
                else:
                    log.info('check test ENV: need uninstall to change HV mode')
                    UninstallFlag = True
            else:
                log.info('check test ENV: need uninstall to change driver version')
                UninstallFlag = True
        else:
            log.info('check test ENV: QAT driver is not installed')

        # uninstall qat driver
        if UninstallFlag:
            log.info('-'*80)
            log.info('QatInstaller.install: uninstall qat driver')

            if os.path.exists(uninstalldriverpath):
                command = r"""Berta-QatDriverUnInstall -DriverPath {0}""".format(uninstalldriverpath)
                out, rc = self.invoke_pscommand(self.pspath, command, 300, shell=False)
                out = self._is_winqat_installed()
                if out:
                    log.info("QatInstaller.install: Uninstall qat driver is failed")
                    self._set_build_id('-1', build_id_file)
                    return {'successful': False, 'error': "Uninstall qat driver is failed"}
                else:
                    log.info('QatInstaller.install: uninstall qat driver is successful')
                    if not uninstalldriverpath == installdriverpath:
                        if os.path.exists(uninstalldriverpath):
                            utils.rm_tree(uninstalldriverpath)
            else:
                log.info("QatInstaller.install: Can not uninstalled, because the qat driver path is not exist")
                return {'successful': False, 'error': "The qat driver path is not exist"}

        # install qat certificate
        log.info('-'*80)

        if not os.path.exists(installdriverpath):
            if self._copy_qat_build(job):
                log.info("QatInstaller.install: Build copied")
            else:
                log.warning("QatInstaller.install: Cannot copy build")
                return {'successful': False, 'error': "Cannot copy build"}

        certfullpath = os.path.join(installdriverpath, "qat_cert.cer")
        log.info('cert full path: {}'.format(certfullpath))

        command = r"""UT-SetCertificate -CertFile {0} -Remote $false""".format(certfullpath)
        out, rc = self.invoke_pscommand(self.pspath, command, 240, shell=False)
        log.info('install certutil command: {}'.format(command))

        # install qat driver
        command = r"""Berta-QatDriverInstall -DriverPath {0} -HVMode ${1} -UQMode ${2}""".format(
            installdriverpath, hyperv_mode, UQ_mode)

        log.info('install command: {}'.format(command))

        out, rc = self.invoke_pscommand(self.pspath, command, 3000, shell=False)

        if self._is_winqat_installed():
            log.info('QatInstaller.install: install qat driver is successful')
            build_id = job['build_id']
            self._set_build_id(build_id, build_id_file)
            return {'successful': True, 'installed': True, 'reboot': False}
        else:
            log.info('QatInstaller.install: install qat driver is failed')
            return {'successful': False, 'installed': False, 'reboot': False}

    def copy_test_dir(self):
        log.info('copy qat test script from repo')
        CopyFlag = False
        command = r"""Berta-CopyTestDir"""
        out, rc = self.invoke_pscommand(self.pspath, command, 500, shell=False)
        out = self.convert_ps_return(out, 'bool')
        if rc == 0:
            if not out:
                CopyFlag = True
        else:
            CopyFlag = True

        if CopyFlag:
            try:
                if os.path.exists(self.QATTEST_DST):
                    shutil.rmtree(self.QATTEST_DST)
                shutil.copytree(self.QATTEST_SRC, self.QATTEST_DST)
            except:
                raise

        return

    # Don't really need to implement because we're re-imaging system per scenario.
    def uninstall(self):
        log.info("QatInstaller.uninstall: initialized")

    @staticmethod
    def convert_ps_return(ps_out, data_type):
        """
        Takes a powershell return (raw string) and converts to python data type

        :param ps_out: the string literal that powershell returned (e.g. stdout)
        :param data_type: the python data type to conver to
        :return: bool, int, float, None
        """
        log.info("QatInstaller.convert_ps_return parameter: {0}".format(ps_out))
        valid_set = set(['bool', 'int', 'float'])
        rv = None

        if data_type in valid_set:
            try:
                if data_type == 'bool':
                    if 'True' in ps_out:
                        rv = True
                    elif 'False' in ps_out:
                        rv =  False
                elif data_type == 'int':
                    rv = int(ps_out)
                elif data_type == 'float':
                    rv = float(ps_out)
            except ValueError:
                log.info("QatInstaller.convert_ps_return value error converting to int or float")
                pass
            except BaseException:
                pass

        log.info("QatInstaller.convert_ps_return return: {0}".format(rv))
        return rv

    @staticmethod
    def get_ps_binary():
        """
        Gets the powershell binary to use, based on system components.

        :return: str, list
        """

        ps7_path = "C:\\Program Files\\Powershell\\7\\pwsh.exe"
        ps5_path = pspath = os.path.join(
            os.environ['SystemRoot'], 'SysNative', 'WindowsPowerShell', 'v1.0', 'powershell.exe')

        if os.path.exists(ps7_path):
            # x64 PS7
            log.info("QatInstaller.get_ps_binary: {0} exists".format(ps7_path))
            pspath = ps7_path
        elif os.path.exists(ps5_path):
            # x64 PS5.1
            log.info("QatInstaller.get_ps_binary: {0} exists".format(ps5_path))
            pspath = ps5_path
        else:
            # Apparently this system doesn't support Powershell?
            raise Exception("System does not appear to have any Powershell.")

        log.info("QatInstaller._get_ps_binary: Return pspath > {0}".format(pspath))

        return pspath

    @staticmethod
    def invoke_pscommand(pspath, command, timeout=60, print_out=True, shell=False):
        """
        Wraps utils.exec_with_timeout to invoke powershell command using pspath

        :param pspath: Path to powershell binary to use. May be str or list.
        :param command: The powershell command to execute.
        :param timeout: Maximum wait time before forcibly ending subprocess.
        :param shell: Flag on whether or not to use the shell.
        :return: str, int
        """

        log.info("QatInstaller.invoke_pscommand: Invoke PS command > {0}".format(command))

        if pspath.endswith("pwsh.exe"):
            # pwsh requires -Command arg
            pscommand = [pspath, '-Command', command]
        elif pspath.endswith("powershell.exe"):
            pscommand = [pspath, command]
        else:
            # Why are we here?
            raise Exception("Invalid pspath")

        out, rc = exec_with_timeout(pscommand, timeout, shell)
        log.info("QatInstaller.invoke_pscommand: Return Code > {0}".format(rc))

        if print_out:
            log.info("QatInstaller.invoke_pscommand: Return Value > \n{0}".format(out))

        return out, rc

    def _copy_qat_build(self, job):
        """
        Copy the Qat Driver to the local_build_dest_dir

        :param job: the job associated with the install
        :return: bool
        """
        log.info("QatInstaller._copy_qat_build: initialized")
        ret = True
        if not self._copy_build(job):
            log.warning("QatInstaller._copy_qat_build: Cannot copy build")
            ret = False

        if job['product'] == self.MS_REPO:
            log.info("QatInstaller._copy_qat_build: MS Repo detected; copying derived driver build")

            # We need to copy the build the MS shared build is derived from
            ms_buildfile = os.path.join(job['build_dest_dir'], job['build_comment'], self.MS_REPO_BUILD_FILE)
            log.info("QatInstaller._copy_qat_build: ms_buildfile > {0}".format(ms_buildfile))

            if os.path.isfile(ms_buildfile):
                with open(ms_buildfile, mode='r') as infile:
                    qat_build = infile.readline()

                qat_build_name = qat_build.split("\\")[1]
                qat_build_dir = os.path.join(self.QATBUILD_ROOT, qat_build)
                local_dest_dir = os.path.join(job['build_dest_dir'], job['build_comment'], qat_build_name)
                log.info("QatInstaller._copy_qat_build: qat_build_dir > {0}".format(qat_build_dir))
                log.info("QatInstaller._copy_qat_build: local_dest_dir > {0}".format(local_dest_dir))
                shutil.copytree(qat_build_dir, local_dest_dir)
            else:
                log.warning("QatInstaller.install: ms_buildfile not found!")
                ret = False
        elif job['product'].startswith(self.PFVF_HEADER):
            log.info("QatInstaller._copy_qat_build: PFVF build detected; copying PF and VF driver build")

            # Check to see if the SPECIAL_BUILD_FILE exists
            pfvf_build_file_path = os.path.join(job['build_dest_dir'], job['build_comment'], self.PF_VF_BUILD_FILE)
            log.info("QatInstaller.install: pfvf_build_file is {0}".format(pfvf_build_file_path))

            """
            Expected build name (folder), strip the PFVF_HEADER
                e.g. Win_QAT17_Master--Linux_QAT17_4.6.0-0001
            Expected filename under folder is PF_VF_BUILD_FILE
            Expected file format is the following. Do not deviate. No spaces in pf/vf path
            PF pf_driver_path
            VF vf_driver_path

            We should only be copying the leaf directory into local_dest_dir (not the whole tree)
            """

            # Copy over the builds (the full folder for each PF and VF)
            if os.path.isfile(pfvf_build_file_path):
                with open(pfvf_build_file_path, mode='r') as infile:
                    for line in infile:
                        if line.startswith("PF") or line.startswith("VF"):
                            # Note that we might not be able to use os.path because these use \\ per Windows standard
                            qat_build_dir = line.rstrip().split(" ")[1]

                            # Below should get the leaf directory
                            qat_build_name = qat_build_dir.split("\\")[-1]

                            local_dest_dir = os.path.join(job['build_dest_dir'], job['build_comment'], qat_build_name)
                            remote_build_dir = os.path.join(self.QATBUILD_ROOT, qat_build_dir)
                            log.info("QatInstaller._copy_qat_build: remote_build_dir > {0}".format(remote_build_dir))
                            log.info("QatInstaller._copy_qat_build: local_dest_dir > {0}".format(local_dest_dir))
                            shutil.copytree(remote_build_dir, local_dest_dir)
                        else:
                            ret = False
                            break
            else:
                log.warning("QatInstaller.install: pfvf_build_file not found!")
                ret = False

        return ret

    def _is_winqat_installed(self):
        """
        Verify installed driver version is same as driver version in build

        :return: bool
        """
        log.info("QatInstaller._is_winqat_installed: initialized")

        command = r"""Berta-QatDriverCheck"""
        out, rc = self.invoke_pscommand(self.pspath, command, 180, shell=False)

        return self.convert_ps_return(out, 'bool')

    def _enable_qat_verifier(self):
        """
        Enables verifier mode for QAT drivers.
        Returns 0 if success otherwise -1.

        :return: int
        """
        log.info("QatInstaller._set_qat_verifier: initialized")

        if True:
            command = r"""Enable-QatVerifier"""
            out, rc = self.invoke_pscommand(self.pspath, command, 60, shell=False)

            if rc == 0:
                rv = self.convert_ps_return(out, 'int')
            else:
                rv = -1

        return rv

    def _verify_winqat_driverversion(self, driverpath):
        """
        Verify installed driver version is same as driver version in build

        :param driverpath: path where driver is located
        :return: bool
        """
        log.info("QatInstaller._verify_winqat_driverversion: initialized")

        command = r"""Test-QatDriverInstall {0}""".format(driverpath)
        out, rc = self.invoke_pscommand(self.pspath, command, 120, shell=False)

        return self.convert_ps_return(out, 'bool')

    def _uninstall_winqat_driver(self, driverpath):
        """
        Uninstall winqat driver

        :param driverpath: path where driver is located
        :return: none
        """
        log.info("QatInstaller._uninstall_winqat_driver")
        command = r"""WBase-QatDriverUnInstall -DriverPath {0}""".format(driverpath)
        _, rc = self.invoke_pscommand(self.pspath, command, 300, shell=False)


if __name__ == "__main__":
    run_wrapper(QatInstaller)
