import time
import os
import logging
import json
import re
import requests

import consts
from utils import Task, exec_with_timeout, join
from wrappers import wrapper
from qatinstaller import QatInstaller
from qatwin_zephyr_mgr import QatwinZephyrManager

log = logging.getLogger(__name__)

'''
The powershell console is opened via popen subprocess, which has the following properties.
    $pshome > C:\Windows\SysNative\WindowsPowerShell\v1.0
    $profile > C:\Users\Administrator\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1
Note that the global PS profile does NOT apply for some reason.

Recommended way to call subprocess is with cmd list:
    [powershell_path, "yourpscommand.ps1"]

Note that the return from this will return ALL console output.
'''

TEST_RESULT_MAP = {
    'PASS': consts.TC_RESULT_PASS,
    'ERRO': consts.TC_RESULT_ERRO,
    'FAIL': consts.TC_RESULT_FAIL,
    'NRUN': consts.TC_RESULT_NRUN
}

HTTP_STATUS_CODE = {
    'OK': 200,
    'TIMEOUT': 503
}

REST_BUILD_STATUS = {
    'BUILT': 'Built',
    'INSTALLED': True,
    'NOT_BUILT': 'Not Built',
    'NOT_INSTALLED': False
}


# Note that this is run entirely in the target system (Windows)
class WinQat(wrapper.ExtendedTestTool):

    # Reboot file in case TC requires reboot
    QATTEST_REBOOTFILE = "C:\\berta\\var\\reboot.txt"
    PARSE_KW_BERTARESULTPATH = 'BertaResultPath'
    PARSE_KW_BUILDPATH = 'bld_path'

    # Required CONSTS
    TEST_TOOL_NAME = 'winqat'
    TEST_TOOL_DIR = 'winqat'
    TEST_LOGS_DIR = 'log'

    # PFVF Special builds
    PFVF_HEADER = "PFVF"
    PF_VF_BUILD_FILE = "pfvf_build.txt"
    PFVF_VM_CONFIG = "vm_config"
    PFVF_TS_CONFIG = "ts_config"

    # No idea what these do
    FILES_TO_COPY = []
    RERUN_TIMEOUTS = False
    FORCE_FLUSH = True

    def __init__(self, scen_file, tool_path, task_id, bld_path, conf_file=None):
        wrapper.ExtendedTestTool.__init__(self, scen_file, tool_path, task_id, bld_path, conf_file)
        self.task = Task(self.task)

        self.zephyr_mgr = QatwinZephyrManager(self.task)
        self.zephyr_enabled = self.zephyr_mgr.zephyr_enabled

        # Note that if we use self.task.get_dir(), it will NOT be available to berta after a system crash
        #  We can use self.task['repo_results_dir'] but you may just end up rerunning the task.
        self.default_result_path = join(self.task.get_dir(), 'results-log.txt')

        self.test_path_root = "C:\\QatTestBerta"
        self.result_file_name = "result.log"

        # Get the scenario args in list form
        self.scenario_list = self._get_scenario_list()

        # Don't initialize yet, because pfvf case will change the args
        self.ps_arg = None

        # Dict of vmname to ipv4 address in pfvf case
        self.vm_to_ipv4_dict = None
        self.vm_config_file = None
        self.ts_config = None

        # The GuestConfig; used in pfvf case to determine what Guest OS to use
        self.GuestConfig = None

        # We assume a 32bit cmd prompt is launched with popen. Thus we use SysNative instead of system32
        self.pspath = QatInstaller.get_ps_binary()

    def prepare_tool(self):
        log.info("Scenario Path: %s" % self.scen_file)
        log.info("Task ID: %s" % self.task_id)
        log.info("Build Path: %s" % self.bld_path)
        log.info("Zephyr Enabled: {}".format(self.zephyr_enabled))

    def prepare_scenario(self):
        # In case we need to do some extra steps for prep
        log.info("WinQat.prepare_scenario: initialized")

        # Check to see if is a Virtualization PF/VF test
        bld_path_dir = self.task.current_job['bld_path'].upper()
        log.info("WinQat.prepare_scenario: bld_path_dir > {}".format(bld_path_dir))

        log.info("WinQat.prepare_scenario: PFVF build detected")

        # TODO: This currently assumes Hyper-V hypervisor; should add check for OS
        #  This can be done based on PF driver info and python os.

        # Get the GuestConfig from Berta config
        self.GuestConfig = self.task.config.get('GuestConfig', None)
        if not self.GuestConfig:
            raise Exception("Unable to find GuestConfg in Berta config")
        log.info("WinQat.prepare_scenario: GuestConfig value > {}\n".format(self.GuestConfig))

        # # Create test vmswitch
        # command = r"""New-TestNetworkVmSwitch"""
        # out, rc = QatInstaller.invoke_pscommand(self.pspath, command, 600, shell=False)
        # if int(out) != 0:
        #     raise Exception("Unable to create Test VMSwitch")

        # # Wait for vmswitch network to come back up
        # time.sleep(30)

        # Prepare test VM's, there needs to be a vm_config arg
        vm_config_list = [r for r in self.scenario_list if re.match(r'{}'.format(self.PFVF_VM_CONFIG), r)]

        if vm_config_list:
            vm_config = ''.join(vm_config_list)
            self.vm_config_file = vm_config.split(" ")[1]
            log.info("WinQat.prepare_scenario: vm_config > {}".format(vm_config))

            # We need to override self.scenario_list to remove vm_config line
            self.scenario_list.remove(vm_config)
            log.info("WinQat.prepare_scenario: Updated scenario_list > {}".format(self.scenario_list))

            # If vm_config None, skip VM Creation
            if self.vm_config_file == "None":
                log.info("WinQat.prepare_scenario: vm_config is None, skipping VM creation.")
                return

            # # Create the test VM's according to config
            # log.info("WinQat.prepare_scenario: Creating VM's.")
            # command = r"""New-TestVirtualMachines -configFile {0} -BertaConfig {1}""".format(self.vm_config_file, self.GuestConfig)
            # out, rc = QatInstaller.invoke_pscommand(self.pspath, command, 1500, shell=False)
        else:
            raise Exception("Unable to find vm_config with PFVF scenario")
        # if int(out) != 0:
        #     raise Exception("Error creating virtual machines")

        # # Wait until virtual machines are connect-able
        # command = r"""Test-ChildVMConnectivity -configFile {0} -BertaConfig {1}""".format(self.vm_config_file, self.GuestConfig)
        # out, rc = QatInstaller.invoke_pscommand(self.pspath, command, 1200, shell=False)
        # if int(out) != 0:
        #     raise Exception("Error waiting for virtual machines to become connect-able")

        # # Get the vmname to ipv4 address dict
        # command = r"""Get-VmIpAddressHash"""
        # out, rc = QatInstaller.invoke_pscommand(self.pspath, command, 1200, shell=False)
        # if not out:
        #     raise Exception("Error receiving VMName to Ipv4 address json")

        # # Populate vm_to_ipv4_dict with the output
        # self.vm_to_ipv4_dict = json.loads(out)

        # Check to see if a testsrv config is present
        ts_config_list = [r for r in self.scenario_list if re.match(r'{}'.format(self.PFVF_TS_CONFIG), r)]

        install_vf = True

        if ts_config_list:
            ts_config = ''.join(ts_config_list)
            self.ts_config = ts_config.split(" ")[1]
            log.info("WinQat.prepare_scenario: ts_config > {}".format(ts_config))

            # We need to override self.scenario_list to remove ts_config line
            self.scenario_list.remove(ts_config)
            log.info("WinQat.prepare_scenario: Updated scenario_list > {}".format(self.scenario_list))

            if self.ts_config == "NoDriver":
                install_vf = False

        # Set the hostname for each virtual machine and install the vf driver package
        """
        for vm_name in self.vm_to_ipv4_dict:
            # Check to see if http server is up
            ip_address = self.vm_to_ipv4_dict[vm_name]['IpAddress']
            rc = self._rest_wait_for_server(ip_address)
            if rc != HTTP_STATUS_CODE['OK']:
                raise Exception("Error waiting for http server on {}".format(ip_address))

            # Set guest repo results path
            rc = self._rest_post_guest_remote_path(ip_address)
            if rc != HTTP_STATUS_CODE['OK']:
                raise Exception("Error setting berta results path on {}".format(vm_name))

            # Set per VM hostname
            # Sometimes hostname set fails, so retry a few times before failing the test
            for i in range(5):
                log.info("WinQat.prepare_scenario: Attempting to set VM hostname, try {}/5".format(i+1))
                rc = self._rest_patch_state(ip_address, Hostname=vm_name)
                if rc == HTTP_STATUS_CODE['OK']:
                    break
                else:
                    log.info("WinQat.prepare_scenario: Hostname set failed, trying again in 5 seconds")
                    time.sleep(5)
            if rc != HTTP_STATUS_CODE['OK']:
                raise Exception("Error setting hostname on {}".format(vm_name))

            if install_vf:
                vf_driver_path = self._get_vf_package_path()
                if vf_driver_path:
                    if self.ts_config:
                        with open(os.path.join(self.test_path_root, "tsconfig", self.ts_config)) as f:
                            data = json.load(f)
                            f.close()
                            rc = self._rest_patch_state_json(ip_address, json.dumps(data))
                            if rc != HTTP_STATUS_CODE['OK']:
                                raise Exception("Error patching config on {}".format(vm_name))

                    rc = self._rest_post_file(ip_address, "driver", vf_driver_path)
                    log.info("WinQat.prepare_scenario: vf driver install return code > {}.".format(rc))
                    if rc != 0:
                        raise Exception("Error install vf driver package on {}".format(vm_name))

                    rc = self._rest_post(ip_address, "build/cpa")
                    if rc != HTTP_STATUS_CODE['OK']:
                        raise Exception("Error building Cpa sample code on {}".format(vm_name))

                    # TODO: We sohuld wait until Cpa is built
                    time.sleep(15)
                else:
                    raise Exception("Unable to get vf driver path")
            else:
                log.info("WinQat.prepare_scenario: ts_config NoDriver flag set, skipping vf driver install.")
            """
        # log.info("WinQat.prepare_scenario: Child VM setup complete.".format(rc))

    def prepare_initial_results(self):
        log.info("WinQat.prepare_initial_results: initialized.")

        # If test is in reboot process, skip this
        self.ps_arg = self._get_command_from_scenario()
        if os.path.isfile(self.QATTEST_REBOOTFILE):
            log.info("WinQat.prepare_initial_results: Skipping prepare initial results due to reboot detected.")
            return

        # Create results-log.txt
        log.info("WinQat.prepare_initial_results: Creating result log at {}".format(self.default_result_path))
        with open(self.default_result_path, 'w+'):
            pass

        # Avoid using task scenario, because ps might not like line return in args
        command = r"""Get-TestCases -Scenario '{0}'""".format(self.ps_arg)
        # log.info("WinQat.prepare_initial_results: Invoke PS command > {}".format(command))
        # out, rc = QatInstaller.invoke_pscommand(self.pspath, command, 4 * 3600, shell=False)
        out = ''
        rc = -1

        # We need to blank lines and strip module load output from out
        output = out.splitlines()
        output = [r for r in output if not re.match(r'^\s*$', r)]
        log.info("WinQat.prepare_initial_results: Formatted output > \n{}".format(output))

        if rc == 0:
            if self.zephyr_enabled:
                log.info("WinQat.prepare_initial_results: Creating zephyr cycle and folder")
                if self.zephyr_mgr.create_zephyr_cycle_and_folder():
                    log.info("WinQat.prepare_initial_results: pulling zephyr issues from jira")
                    self.zephyr_mgr.pull_all_jira_issues()
                else:
                    log.error("WinQat.prepare_initial_results: error creating zephyr structure, disabling zephyr reporting")
                    self.zephyr_enabled = False
            try:
                for line in output:
                    # Update berta NRUN results
                    log.info("WinQat.prepare_initial_results: Adding to NRUN > {0}".format(line))
                    result = {'status': TEST_RESULT_MAP['NRUN'], 'cmd_line': ""}
                    self.update_result(line, **result)

                    if self.zephyr_enabled:
                        issue_id = self.zephyr_mgr.find_issue_for_testcase(line)
                        if issue_id:
                            log.info("WinQat.prepare_initial_results: issue {0} found for testcase {1}".format(issue_id, line))
                            execution_id = self.zephyr_mgr.add_execution_to_folder(issue_id)
                            if execution_id:
                                log.info("WinQat.prepare_initial_results: mapping testcase {0} to execution {1}".format(line, execution_id))
                                self.zephyr_mgr.map_tc_to_execution(line, execution_id)
                        else:
                            self.zephyr_mgr.store_missing(line)
                if self.zephyr_mgr.missing_tc_present:
                    log.info("WinQat.prepare_initial_results: berta test cases missing zephyr issue:")
                    for tc in self.zephyr_mgr.missing_tc:
                        log.info("WinQat.prepare_initial_results: {}".format(tc))
            except BaseException as e:
                raise Exception("Error parsing return output: {}".format(e))
        elif rc == -1:
            log.info("WinQat.prepare_initial_results: No scenario prepare is defined.")
        else:
            raise Exception("Non-zero return code, likely an error.")

    def run_testing(self):
        log.info("WinQat.run_testing: initialized")
        """
        Scheduler will pad timeout by 10 min, so we need to reduce this
            in order for there to be sufficient time for agent update in event of timeout.
        Additionally, Agent will wait 5 minutes to force terminate.
        """

        pstimeout = ((self.task.current_job['timeout'] - 18) * 60)
        log.info("WinQat.run_testing: PSScript > {0}".format(self.ps_arg))
        log.info("WinQat.run_testing: PSTimeout > {0}".format(pstimeout))

        # Create empty results file
        result_file = os.path.join(self.task['task_dir'], self.result_file_name)

        """
        For whatever reason, when a valid results.log is present after system crash,
        run_testing will proceed to redo the task.
        log.info("Creating result log at {}".format(result_file))
        with open(result_file, 'w+'):
            pass
        """

        # In PFVF case, check to see if the number of VF's are as expected
        if self.vm_config_file == "None":
            # No VM's are created; skip check
            log.info("WinQat.run_testing: skipping QAT VF numbers check.")
        else:
            bld_path_dir = self.task.current_job['bld_path'].upper()
            log.info("WinQat.run_testing: bld_path_dir > {}".format(bld_path_dir))
            if os.path.basename(bld_path_dir).upper().startswith(self.PFVF_HEADER):
                command = r"""Test-QatVfNumber -configFile {0} -BertaConfig {1}""".format(self.vm_config_file, self.GuestConfig)
                out, rc = QatInstaller.invoke_pscommand(self.pspath, command, 60, shell=False)

                if int(out.rstrip()) != 0:
                    # Number of VF's are not as expected
                    raise Exception("WinQat.run_testing: VF Number mismatching, canceling test.")

        command = r"""{0}\{1}""".format(self.test_path_root, self.ps_arg)
        _, rc = QatInstaller.invoke_pscommand(self.pspath, command, pstimeout, print_out=False, shell=False)

        """
        How to use reboot mechanism:
            1. Have your script write to the QATTEST_REBOOTFILE file.
            2. Exit script, and Berta agent will reboot
            3. Write an if statement surrounding reboot file handling.
            4. When you're done with reboots, simply write Finished (or remove file).
            5. Berta agent will remove file and post results.
        """
        # Check if reboot file is present, it will set reboot to true
        if os.path.isfile(self.QATTEST_REBOOTFILE):
            with open(self.QATTEST_REBOOTFILE, 'r') as infile:
                reboot_contents = infile.read()

            log.info("WinQat.run_testing: Found reboot file contents > {}".format(reboot_contents))

            # Powershell outfile creates a line break at the end
            reboot_contents = reboot_contents.rstrip()
            log.info(reboot_contents)

            if reboot_contents.lower() == 'finished':
                os.remove(self.QATTEST_REBOOTFILE)
                time.sleep(60)
            else:
                log.info("WinQat.run_testing: Set status to reboot")
                self.reboot()

        if not os.path.isfile(self.QATTEST_REBOOTFILE):
            # Now we need to let berta update the results
            log.info("WinQat.run_testing: Update result_file > {0}".format(result_file))

            # Check to see if the results file exists (may not if system crash before result file creation)
            # if os.path.exists(result_file):
            with open(result_file, mode='r') as infile:
                for line in infile:
                    jsonline = json.loads(line)
                    log.info(jsonline)
                    result = {'status': TEST_RESULT_MAP.get(jsonline.get('s'), TEST_RESULT_MAP.get('NRUN'))}
                    result.update({'cmd_line': jsonline.get('cmd', '')})
                    result.update(jsonline.get('v', {}))
                    self.update_result(jsonline['tc'], **result)
                    if self.zephyr_enabled:
                        log.info("WinQat.run_testing: Storing result {0}:{1} for zephyr report".format(jsonline['tc'], jsonline['s']))
                        self.zephyr_mgr.store_execution_result(jsonline['tc'], jsonline['s'])
            if self.zephyr_enabled:
                log.info("WinQat.run_testing: Uploading results to zephyr")
                self.zephyr_mgr.bulk_update_execution_results()

            """
            for the new testsrv log copy, we dont set log/output path to /mnt/berta anymore, it was causing issues
            new endpoint /logcopy will copy test, build and server logs to a new folder created in the local dir of the
            remote mount, typically /mnt/berta.  folder name is the vm hostname
            optionally, this endpoint can take json body in the form:
            {
                "CopyTargets": ["server", "build", "test"],
                "ExtraDir": ["1vm_1vf"]
            }
            Where CopyTargets controls which logs are copied, and ExtraDir creates additional sub directories in the
            berta results dir.  For example, with the above config, all logs will be copied into directory
            /mnt/berta/1vm_1vf/<vm_hostname>/x.log
            """
            if self.vm_to_ipv4_dict:
                for vm_name in self.vm_to_ipv4_dict:
                    log.info("WinQat.run_testing: Copying testsrv logs from vm {}".format(vm_name))
                    ip_address = self.vm_to_ipv4_dict[vm_name]['IpAddress']
                    rc = self._rest_post(ip_address, "logcopy")
                    if rc != 0:
                        log.info("WinQat.run_testing: Copy failed")

            # Add file compression to working directory and repo directory.
            command = r"""Berta-CompressReturnFiles -Path {0}""".format(self.task['repo_results_dir'])
            _, _ = QatInstaller.invoke_pscommand(self.pspath, command, 600, shell=False)

            command = r"""Berta-CompressReturnFiles -Path {0}""".format(self.task['task_dir'])
            _, _ = QatInstaller.invoke_pscommand(self.pspath, command, 600, shell=False)

        # Note that the driver is installed and system is in whatever state the test leaves it at.

    @staticmethod
    def _rest_get_driver_state(ip_address):
        """
        This issues returns the state of system with ip_address
        Returns 0 if driver is Built, otherwise -1

        :param ip_address: ip address of the system
        :return: int
        """

        http_server = r"""http://{}:8080/state""".format(ip_address)
        out = requests.get(http_server)
        json_out = json.loads(out.content)

        if (json_out['ServerState']['BuildStatus'] == REST_BUILD_STATUS['BUILT'] and
                json_out['ServerState']['QATInstalled'] == REST_BUILD_STATUS['INSTALLED']):

            rc = 0
        else:
            rc = -1

        return rc

    @staticmethod
    def _rest_patch_state(ip_address, **kwargs):
        """
        This issues a request to patch vm with ip_address.
        Returns the last HTTP status code. Will stop on bad HTTP status code.

        Acceptable kwargs: Hostname, OutputPath, TestTimeout

        :param ip_address: ip address of the system
        :param kwargs: kwargs
        :return: int
        """

        header = {"Content-type": "application/json"}

        for key, value in kwargs.items():
            data = r"""{{"{}": "{}"}}""".format(key, value)
            http_server = r"""http://{}:8080/state""".format(ip_address)
            log.info("WinQat._rest_patch_state: http_server '{}' patch '{}'".format(http_server, data))
            out = requests.patch(http_server, headers=header, data=data)
            http_sc = out.status_code

            log.info("WinQat._rest_patch_state: http server at '{}' returns > {}".format(http_server, http_sc))
            log.info("WinQAT._rest_patch_state: http content: {}".format(out.content))
            if http_sc != HTTP_STATUS_CODE['OK']:
                break

        return http_sc

    @staticmethod
    def _rest_patch_state_json(ip_address, json_data):
        """
        This issues a request to patch vm with ip address with json data
        Returns http status code

        :param ip_address: ip address of the vm
        :param json_data: data to patch.  should be in the form of testsrv cfg.json
        :return: int
        """

        # TODO: validate json input

        http_server = r"""http://{}:8080/state""".format(ip_address)

        log.info("WinQat._rest_patch_state: http_server '{}' patch '{}'".format(http_server, json_data))
        out = requests.patch(http_server, headers={"Content-type": "application/json"}, data=json_data)
        log.info("WinQat._rest_patch_state: http server at '{}' returns > {}".format(http_server, out.status_code))
        log.info("WinQAT._rest_patch_state: http content: {}".format(out.content))

        return out.status_code

    @staticmethod
    def _rest_post(ip_address, subdirectory):
        """
        This issues a post request to the http_server
        Returns HTTP status code of the request.

        :param ip_address: ip address of the http server
        :param subdirectory: the subdirectory
        :return: int
        """

        http_server = r"""http://{}:8080/{}""".format(ip_address, subdirectory)
        out = requests.post(http_server)
        log.info("WinQat._rest_post: http server at '{}' returns > {}".format(http_server, out.status_code))
        log.info("WinQAT._rest_post: http content: {}".format(out.content))
        return out.status_code

    def _rest_post_file(self, ip_address, endpoint, file_path, retry=10):
        """
        This issues a request to install the vf driver to http_server
        Returns 0 if success, -[int] if failure.

        :param ip_address: ip address of the http server
        :param endpoint: type of file to test (e.g. driver or samplecode)
        :param file_path: driver package file path
        :param retry: how many times to retry
        :return: int
        """

        http_server = r"""http://{}:8080/build/upload/{}""".format(ip_address, endpoint)
        files = {'image': open(file_path, 'rb')}
        out = requests.post(http_server, files=files)
        http_sc = out.status_code
        http_content = out.content
        log.info("WinQat._rest_post_file: http server at '{}' returns > {}".format(http_server, http_sc))
        log.info("WinQat._rest_post_file: http content > {}".format(http_content))

        if http_sc != HTTP_STATUS_CODE['OK']:
            rc = -2
        else:
            # Loop to check build status
            time.sleep(30)

            for i in range(retry):
                rc = self._rest_get_driver_state(ip_address)
                log.info("WinQat._rest_post_file: get driver state return  > {}".format(rc))
                if rc == 0:
                    break
                time.sleep(120)

        return rc

    def _rest_post_guest_remote_path(self, ip_address):
        """
        This issues a request to patch vm with remote berta path.
        Returns the last HTTP status code.

        :param ip_address: ip address of the system
        :return: int
        """

        # Note this assumes Windows host; need to ifdef for Linux host
        command = r"""Get-BertaSharePath -BertaResultPath {}""".format(self.task['task_dir'])
        remote_path_full, rc = QatInstaller.invoke_pscommand(self.pspath, command, 30, shell=False)
        remote_path_full = remote_path_full.rstrip()
        log.info("WinQat._rest_post_guest_remote_path: result_path_full > \n{}".format(remote_path_full))

        http_server = r"""http://{}:8080/mount""".format(ip_address)
        header = {"Content-type": "application/json"}
        data = r"""{{"RemotePath": "{}", "LocalPath": "/mnt/berta"}}""".format(remote_path_full)
        log.info("WinQat._rest_post_remote_path: http_server '{}' post '{}'".format(http_server, data))

        out = requests.post(http_server, headers=header, data=data)

        log.info("WinQat._rest_post_guest_remote_path: http server at '{}' returns > {}".format(http_server, out.status_code))
        log.info("WinQat._rest_post_guest_remote_path: http content > {}".format(out.content))

        return out.status_code

    @staticmethod
    def _rest_wait_for_server(ip_address, retry=10):
        """
        This will wait for the http server to come up at ip_address given timeout.
        Returns the HTTP status code.

        :param ip_address: ip address of the http server
        :param retry: how many times to retry
        :return: int
        """

        http_server = r"""http://{}:8080/state""".format(ip_address)
        for i in range(retry):
            try:
                http_sc = HTTP_STATUS_CODE['TIMEOUT']
                out = requests.get(http_server)
                http_sc = out.status_code
            except requests.exceptions.ConnectionError:
                # Assume that the service may not be up
                log.info("WinQat._rest_wait_for_server: http server '{}' is down.".format(http_server))
            except BaseException:
                log.info("WinQat._rest_wait_for_server: http server '{}' has unknown exception.".format(http_server))

            if http_sc == HTTP_STATUS_CODE['OK']:
                json_out = json.loads(out.content)
                log.info("WinQat._rest_wait_for_server: http server version is {}.".format(json_out['ServerVersion']))
                break
            else:
                log.info("WinQat._rest_wait_for_server: http server at '{}' returns > {}".format(http_server, http_sc))
                time.sleep(60)

        return http_sc

    def _get_command_from_scenario(self):
        """
        This takes berta scenario entry and converts to a command to execute.
        By the time we get to here, the first entry is the test script.
        We should only execute one scenario ps1 at a time, structure is:
            ScenarioName (with extension, e.g. ParcompParameter.ps1)
            BertaResultsPath self.task['task_dir'] (this is required)
            ParameterName Argument
            ParameterName Argument

        :return: string
        """

        try:
            ps_arg = self.scenario_list.pop(0)
            ps_arg = "{0} -{1} {2}".format(ps_arg, self.PARSE_KW_BERTARESULTPATH, self.task['task_dir'])

            for line in self.scenario_list:

                # Check for quotes (assumption is multi word arg); based on double quotation
                m = re.match(r"""(?P<arg_1>\w+) (?P<arg_2>\".*?\")""", line)
                if m:
                    arg_1 = m.group('arg_1')
                    arg_2 = m.group('arg_2')
                else:
                    args = line.split()
                    if len(args) == 2:
                        # Assumption is that this is the ParameterName Argument line
                        arg_1 = args[0]

                        # Look for parse keywords
                        if args[1] == self.PARSE_KW_BUILDPATH:
                            arg_2 = self.task.current_job['bld_path']
                        else:
                            arg_2 = args[1]
                    else:
                        raise IndexError("Unexpected scenario line length")
                log.info("WinQat._get_command_from_scenario: arg_1 is {} ; arg_2 is {}".format(arg_1, arg_2))
                ps_arg = "{0} -{1} {2}".format(ps_arg, arg_1, arg_2)
        except BaseException as e:
            raise Exception("Error while parsing scenario arguments: {}".format(e))

        log.info("WinQat._get_command_from_scenario: ps_arg > {0}".format(ps_arg))
        return ps_arg

    def _get_scenario_list(self):
        """
        This takes berta scenario entry and converts to a list.

        :return: list(str)
        """

        # Example: scen = "\ntest\nparam 1\nparam 2\nparam repo_dir\nparam bld_path\n  \n\n".splitlines()
        scen = self.task.current_job['scenario'].splitlines()
        scen = [r for r in scen if not re.match(r'^\s*$', r)]

        return scen

    def _get_vf_package_path(self):
        """
        This parses PF_VF_BUILD_FILE and returns the path of the zip/tarball
        Returns None if it cannot find anything

        :return: str
        """

        rv = None

        # Determine what is the vf driver
        pfvf_build_file = os.path.join(self.task.current_job['bld_path'], self.PF_VF_BUILD_FILE)
        with open(pfvf_build_file, mode='r') as infile:
            for line in infile:
                if line.startswith('VF'):
                    qat_build_dir = line.rstrip().split(" ")[1]
                    break

        if qat_build_dir:
            leaf_directory = os.path.basename(qat_build_dir).lower()
            match = r"(qat\d.\d(_dev)?.)(?P<vf_os>\w+)"
            m = re.match(match, leaf_directory)

            if m:
                vf_os = m.group('vf_os')
                log.info("WinQat._get_vf_package_path: OS Id string > {}".format(vf_os))

                if vf_os == 'l':
                    vf_file = leaf_directory + ".tar.gz"
                elif vf_os == 'w':
                    vf_file = leaf_directory + ".zip"
                else:
                    raise Exception("Unknown OS version in {}".format(leaf_directory))

                rv = os.path.join(self.task.current_job['bld_path'], leaf_directory, vf_file)
                log.info("WinQat._get_vf_package_path: vf package path > {}".format(rv))
            else:
                raise Exception("Unable to find OS version in {}".format(leaf_directory))
        else:
            raise Exception("Unable to find VF driver directory")

        return rv


if __name__ == "__main__":
    wrapper.run(WinQat)
