#!/usr/bin/env python
"""

Customization script for Self-Service VM Provisioning via Nutanix Prism
Central. Invoked by cloud-init (Linux) and cloudbase-init (Windows)
when a VM is provisioned by an end user.
Performs a single reboot for Linux and 3 reboots for Windows.

"""


__version__ = '3.0'
__author__ = 'cybergavin'
__email__ = 'cybergavin@gmail.com'


import logging
import sys
import configparser
import json
import platform
import subprocess
from pathlib import Path, PurePath
from time import sleep

import requests

requests.packages.urllib3.disable_warnings()

try:
    # Variables
    script_host = platform.node()
    script_os = platform.system()
    script_dir = Path((PurePath(sys.argv[0]).parent)).resolve(strict=True)
    script_name = PurePath(sys.argv[0]).name
    script_stem = PurePath(sys.argv[0]).stem
    log_file = script_dir / f'{script_stem}.log'
    cfg_file = script_dir / f'{script_stem}.cfg'
    cred_file = script_dir / f'{script_stem}.cred'
    run_file = script_dir / f'{script_stem}.running'
   

    # Set up Logger
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    _FORMAT = '%(asctime)s.%(msecs)03d — %(module)s:%(name)s:%(lineno)d — %(levelname)s — %(message)s'
    formatter = logging.Formatter(_FORMAT, datefmt='%Y-%b-%d %H:%M:%S')
    console_handler = logging.StreamHandler(sys.stdout)
    file_handler = logging.FileHandler(log_file, mode='a')
    console_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)
    console_handler.setLevel(logging.INFO)
    file_handler.setLevel(logging.DEBUG)
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    logger.debug('script_dir=%s|log_file=%s', script_dir, log_file)
    logger.debug('cfg_file=%s|cred_file=%s', cfg_file, cred_file)

    # Validation
    if not sys.version_info.major == 3 and sys.version_info.minor >= 5:
        logger.critical('This script requires Python version >= 3.5.')
        sys.exit()
    if not Path(cfg_file).exists():
        logger.critical('Missing required file %s.', cfg_file)
        sys.exit()
    if not Path(cred_file).exists():
        logger.critical('Missing required file %s.', cred_file)
        sys.exit()

    # Parsing configuration and credential files
    config = configparser.ConfigParser(interpolation=None)
    config.read([cfg_file, cred_file])
    ntx_pc_url = f'https://{config["ntx_prism"]["ntx_pc_fqdn"]}:9440/api/nutanix/v3'
    prism_timeout = int(config['ntx_prism']['timeout'])
    ad_domain = config['ms_ad']['ad_domain']
    ad_fqdn = config['ms_ad']['ad_fqdn']
    ad_ou = config['ms_ad']['ad_ou']
    linux_admins = config['ms_ad']['linux_admins']
    windows_admins = config['ms_ad']['windows_admins']
    ntx_pc_auth = config['ntx_prism']['ntx_pc_auth']
    ad_bind_user = config['ad_bind']['ad_bind_user']
    ad_bind_password = config['ad_bind']['ad_bind_password']
    
    # Variables for REST API calls to Prism Central
    headers = {'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Authorization': f'Basic {ntx_pc_auth}'}
    vm_filter = {'kind': 'vm','filter': f'vm_name=={script_host}'}
    vm_ngt = {"nutanix_guest_tools": {"iso_mount_state":"MOUNTED","enabled_capability_list": ["SELF_SERVICE_RESTORE","VSS_SNAPSHOT"],"state":"ENABLED"}}

    logger.debug('Parsed files %s and %s. Available sections are %s',
    cfg_file, cred_file, config.sections())
    logger.debug('Nutanix Prism Central URL is %s', ntx_pc_url)
    logger.info('Parsed configuration and credential files')

    logger.debug('Validation checks PASSED')

    '''
    Use run_file to pass values between Windows VM reboots.
    run_file is not used for Linux VM customization
    '''
    if not Path(run_file).exists():
        # Get VM's Metadata from Nutanix Prism Central
        try:
            md_response = requests.post(
                f'{ntx_pc_url}/vms/list',
                headers=headers,
                data=json.dumps(vm_filter),
                timeout=prism_timeout,
                verify=False)
            md_json = md_response.json()
            md_response.raise_for_status()
        except requests.exceptions.HTTPError as err_http:
            logger.error(err_http)
            sys.exit()
        except requests.exceptions.ConnectionError as err_conn:
            logger.error(err_conn)
            sys.exit()
        except requests.exceptions.Timeout as err_timeout:
            logger.error(err_timeout)
            sys.exit()
        except requests.exceptions.RequestException as err:
            logger.error(err)
            sys.exit()

        logger.info('Successfully called Prism Central API for VM spec')
        logger.debug('VM spec JSON from Prism Central. \n %s', json.dumps(md_json,indent=4))

        try:
            ssvm_uuid = md_json["entities"][-1]["metadata"]["uuid"]
            ssvm_project = md_json["entities"][-1]["metadata"]["project_reference"]["name"]
            ssvm_owner = md_json["entities"][-1]["metadata"]["owner_reference"]["name"]
        except KeyError as ke:
            logger.error('Encountered KeyError while obtaining VM Metadata \n %s',ke)
            sys.exit()            
        
        logger.debug('UUID=%s|PROJECT=%s|OWNER=%s', ssvm_uuid, ssvm_project, ssvm_owner)
        logger.info('Obtained the required metadata from Prism Central.')

        '''
        Generate a new hostname for other IT systems (AD/Patching/etc.)
        Modified hostname -> upto 12 characters of provided name combined with
        '-NN', where NN are the last 2 characters of the project name. This
        allows for unique names across (but not within) Nutanix projects
        '''
        mon_host = f'{script_host[:12]}-{ssvm_project[-2:]}'

        '''
        Get the VM's latest spec (due to a current bug in different spec_version returned
        in previous POST while creating VM and subsequent GET) for update.
        '''
        try:
            vm_spec_res = requests.get(
                f'{ntx_pc_url}/vms/{ssvm_uuid}',
                headers=headers,
                timeout=prism_timeout,
                verify=False)
            vm_spec = vm_spec_res.json()
            vm_spec_res.raise_for_status()
        except requests.exceptions.HTTPError as err_http:
            logger.error(err_http)
            sys.exit()            
        except requests.exceptions.ConnectionError as err_conn:
            logger.error(err_conn)
            sys.exit()            
        except requests.exceptions.Timeout as err_timeout:
            logger.error(err_timeout)
            sys.exit()            
        except requests.exceptions.RequestException as err:
            logger.error(err)
            sys.exit()            

        logger.info('Successfully called Prism Central API for latest VM spec')
        logger.debug('Latest VM spec JSON from Prism Central. \n %s', json.dumps(vm_spec,indent=4))
        
        # Prepare VM spec for VM Update
        new_vm_spec = {}
        new_vm_spec["api_version"] = vm_spec["api_version"]
        new_vm_spec["spec"] = vm_spec["spec"]
        new_vm_spec["spec"]["name"] = mon_host        
        new_vm_spec["spec"]["resources"]["guest_tools"] = vm_ngt
        new_vm_spec["metadata"] = vm_spec["metadata"]
        new_vm_spec["metadata"]["categories_mapping"] = { "Self-Service": [f"{ssvm_project}"]}
        new_vm_spec["metadata"]["categories"] = { "Self-Service": f"{ssvm_project}"}

        # Update VM - change hostname, mount Nutanix Guest Tools and update VM's categories
        try:
            update_vm_res = requests.put(
                f'{ntx_pc_url}/vms/{ssvm_uuid}',
                headers=headers,
                data=json.dumps(new_vm_spec),
                timeout=prism_timeout,
                verify=False)
            update_vm_json = update_vm_res.json()
            update_vm_res.raise_for_status()
        except requests.exceptions.HTTPError as err_http:
            logger.error(err_http)
            sys.exit()            
        except requests.exceptions.ConnectionError as err_conn:
            logger.error(err_conn)
            sys.exit()            
        except requests.exceptions.Timeout as err_timeout:
            logger.error(err_timeout)
            sys.exit()            
        except requests.exceptions.RequestException as err:
            logger.error(err)
            sys.exit()            

        logger.debug('JSON Response from Prism Central for updating VM \n %s',json.dumps(update_vm_json,indent=4))
        logger.info('Successfully called Prism Central to update the VM')
        sleep(10)

        # Customize VM
        if script_os.upper() == 'LINUX':
            hostname_cmd = (
                f'hostnamectl set-hostname {mon_host}'
            )
            ad_join_cmd = (
                f'echo "{ad_bind_password}" | realm join "{ad_fqdn}" '
                f'--computer-ou="{ad_ou}" '
                f'-U "{ad_bind_user}"'
            )
            ENABLE_SSSD_CMD = (
                'systemctl enable sssd && '
                'sed -i "s/use_fully_qualified_names = True/use_fully_qualified_names = False/" '
                '/etc/sssd/sssd.conf'
            )
            adminaccess_cmd = (
                f'realm deny --all && '
                f'realm permit -g "{ad_domain}\{linux_admins}" && '
                f'echo \'"%{linux_admins}" ALL=(ALL) NOPASSWD: ALL\''
                f'>> /etc/sudoers'
            )
            if ssvm_project and ssvm_owner:
                useraccess_cmd = (
                    f'realm permit -g "{ad_domain}\{ssvm_project}" && '
                    f'echo \'{ssvm_owner[:ssvm_owner.rfind("@")]} ALL=(ALL) NOPASSWD: ALL\''
                    f'>> /etc/sudoers'
                    )
            with open(log_file, 'a') as _lf:
                if not subprocess.run(
                    f'{hostname_cmd}',
                    shell=True,
                    stdout=_lf,
                    stderr=_lf).returncode:
                    logger.info('Renamed VM %s to %s before joining %s AD Domain',
                    script_host, mon_host, ad_domain)
                else:
                    logger.error('Failed to rename VM %s before joining the %s AD Domain',
                    script_host, ad_domain)
                if not subprocess.run(
                    f'{ad_join_cmd}',
                    shell=True,
                    stdout=_lf,
                    stderr=_lf).returncode:
                    logger.info('Joined VM %s to the %s AD Domain', mon_host, ad_domain)
                else:
                    logger.error('Failed to join VM %s to the %s AD Domain',
                    mon_host, ad_domain)
                if not subprocess.run(
                    f'{ENABLE_SSSD_CMD}',
                    shell=True,
                    stdout=_lf,
                    stderr=_lf).returncode:
                    logger.info('Configured and enabled SSSD')
                else:
                    logger.error('Failed to configure/enable SSSD')
                if not subprocess.run(
                    f'{adminaccess_cmd}',
                    shell=True,
                    stdout=_lf,
                    stderr=_lf).returncode:
                    logger.info('Provisioned Admin access to the VM.')
                else:
                    logger.error('Failed to provision Admin access to the VM.')
                if ssvm_project and ssvm_owner:
                    if not subprocess.run(
                        f'{useraccess_cmd}',
                        shell=True,
                        stdout=_lf,
                        stderr=_lf).returncode:
                        logger.info('Provisioned SSH access to the VM for %s\\%s AD group '
                        'and sudo privileges for user %s', ad_domain,
                        ssvm_project, ssvm_owner[:ssvm_owner.rfind("@")])
                    else:
                        logger.error('Failed to provision user access to the VM.')
                if not subprocess.run(
                    'systemctl restart sssd',
                    shell=True,
                    stdout=_lf,
                    stderr=_lf).returncode:
                    logger.info('Restarted the SSSD service.')
                else:
                    logger.error('Failed to restart the SSSD service.')
                if not subprocess.run('systemctl restart ngt_guest_agent',
                    shell=True,
                    stdout=_lf,
                    stderr=_lf).returncode:
                    logger.info('Restarted the Nutanix Guest Agent service.')
                else:
                    logger.error('Failed to restart the Nutanix Guest Agent service.')                                     

                # Disable cloud-init to prevent reverting the hostname
                Path("/etc/cloud/cloud-init.disabled").touch()
                if Path("/etc/cloud/cloud-init.disabled").exists():
                    logger.info('Disabled the cloud-init service')
                else:
                    logger.error('Failed to disable the cloud-init service')

        if script_os.upper() == 'WINDOWS':
            # Log data in run_file for next run after Windows VM reboot
            # Change hostname and reboot with exit code 1003 to signal to
            # Cloudbase-init to rerun this program after reboot
            with open(run_file, "a") as text_file:
                print(f'ssvm_project={ssvm_project}', file=text_file)
                print(f'ssvm_owner={ssvm_owner}', file=text_file)
            hostname_cmd = (
                f'netdom renamecomputer {script_host} '
                f'/newname:{mon_host} '
                f'/force'
            )
            with open(log_file, 'a') as _lf:
                if not subprocess.run(
                    f'{hostname_cmd}',
                    shell=True,
                    stdout=_lf,
                    stderr=_lf).returncode:
                    logger.info('Renamed VM %s to %s',script_host, mon_host)
                    sys.exit(1003)
                else:
                    logger.error('Failed to rename VM %s to %s',
                    script_host, mon_host)
                    sys.exit(911)
    else:
        # Entering Windows reboot re-run block for further customization
        ntx_fetched = {}
        with open(run_file) as f:
            for line in f.readlines():
                key, value = line.rstrip("\n").split("=")
                ntx_fetched[key] = value
        ssvm_project = ntx_fetched["ssvm_project"]
        ssvm_owner = ntx_fetched["ssvm_owner"]
        if not ssvm_project and ssvm_owner:
            log.error('Could not determine project and owner from run file. Exiting.')
            sys.exit()
            
        logger.debug('ntx_fetched values are ssvm_project = %s and '
        'ssvm_owner = %s', ssvm_project,ssvm_owner)

        ad_join_cmd = (
            f'netdom join {script_host} '
            f'/ou:"{ad_ou}" '
            f'/domain:{ad_fqdn} '
            f'/ud:{ad_domain}\\{ad_bind_user} '
            f'/pd:"{ad_bind_password}"'
            )

        adminaccess_cmd = (
            f'net localgroup Administrators "{windows_admins}" /ADD'
            )

        useraccess_cmd = (
            f'net localgroup "Remote Desktop Users" '
            f'"{ssvm_project}" /ADD && '
            f'net localgroup Administrators '
            f'{ssvm_owner[:ssvm_owner.rfind("@")]} /ADD'
            )

        NGA_RESTART_CMD = (
            'net stop "Nutanix Guest Agent" && '
            'net start "Nutanix Guest Agent"'
            )

        with open(log_file, 'a') as _lf:
            if not subprocess.run(
                f'{ad_join_cmd}',
                shell=True,
                stdout=_lf,
                stderr=_lf).returncode:
                logger.info('Joined VM %s to the %s AD Domain',
                script_host, ad_domain)
                sleep(5)
            else:
                logger.error('Failed to join VM %s to the %s AD Domain',
                script_host, ad_domain)
            if not subprocess.run(
                f'{adminaccess_cmd}',
                shell=True,
                stdout=_lf,
                stderr=_lf).returncode:
                logger.info('Provisioned Admin access to the VM.')
            else:
                logger.error('Failed to provision Admin access to the VM.')

            if ssvm_project and ssvm_owner:
                if not subprocess.run(
                    f'{useraccess_cmd}',
                    shell=True,
                    stdout=_lf,
                    stderr=_lf).returncode:
                    logger.info('Provisioned standard RDP access to the VM '
                    'for %s\\%s AD group and Administrator privileges for user %s',
                    ad_domain, ssvm_project, ssvm_owner[:ssvm_owner.rfind("@")])
                else:
                    logger.error('Failed to provision user access to the VM.')

            if not subprocess.run(
                f'{NGA_RESTART_CMD}',
                shell=True,
                stdout=_lf,
                stderr=_lf).returncode:
                logger.info('Restarted the Nutanix Guest Agent service.')
            else:
                logger.error('Failed to restart the Nutanix Guest Agent service.')
except Exception as ex:
    logger.exception('Encountered unhandled exception\n %s',ex)
    if Path(cred_file).exists():
        Path(cred_file).unlink()

# Cleanup
if Path(cred_file).exists():
    Path(cred_file).unlink()
if Path(run_file).exists():
    Path(run_file).unlink()    

# Cloudbase-init exit for Windows to prevent re-execution upon boot.
if script_os.upper() == 'WINDOWS':
    sys.exit(1001)
