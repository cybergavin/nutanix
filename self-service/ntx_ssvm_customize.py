#!/usr/bin/env python
"""

Customization script for Self-Service VM Provisioning via Nutanix Prism
Central. Invoked by cloud-init (Linux) and cloudbase-init (Windows)
when a VM is provisioned by an end user.

"""


__version__ = '2.0'
__author__ = 'cybergavin'


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

    # Set up Logger
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    _FORMAT = '%(asctime)s.%(msecs)03d — %(module)s:%(name)s:%(lineno)d — %(levelname)s — %(message)s'
    formatter = logging.Formatter(_FORMAT, datefmt='%Y-%b-%d %H:%M:%S')
    console_handler = logging.StreamHandler(sys.stdout)
    file_handler = logging.FileHandler(log_file, mode='w')
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
    config = configparser.ConfigParser()
    config.read([cfg_file, cred_file])
    ntx_pc_url = f'https://{config["ntx_prism"]["ntx_pc_fqdn"]}:9440/api/nutanix/v3'
    ntx_pe_url = f'https://{config["ntx_prism"]["ntx_pe_fqdn"]}:9440/PrismGateway/services/rest/v1'
    prism_timeout = int(config['ntx_prism']['timeout'])
    ad_domain = config['ms_ad']['ad_domain']
    ad_fqdn = config['ms_ad']['ad_fqdn']
    linux_admins = config['ms_ad']['linux_admins']
    windows_admins = config['ms_ad']['windows_admins']
    ntx_pc_auth = config['ntx_prism']['ntx_pc_auth']
    ntx_pe_auth = config['ntx_prism']['ntx_pe_auth']
    ad_bind_user = config['ad_bind']['ad_bind_user']
    ad_bind_password = config['ad_bind']['ad_bind_password']

    logger.debug('Parsed files %s and %s. Available sections are %s',
    cfg_file, cred_file, config.sections())
    logger.debug('Nutanix Prism Central URL is %s', ntx_pc_url)
    logger.debug('Nutanix Prism Element URL is %s', ntx_pe_url)
    logger.info('Parsed configuration and credential files')

    logger.debug('Validation checks PASSED')

    # Get VM's Metadata from Nutanix Prism Central
    headers = {'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Authorization': f'Basic {ntx_pc_auth}'}
    data = {'kind': 'vm',
    'filter': f'vm_name=={script_host}'}
    md_response = requests.post(
        f'{ntx_pc_url}/vms/list',
        headers=headers,
        data=json.dumps(data),
        timeout=prism_timeout,
        verify=False)
    md_json = md_response.json()
    logger.debug('JSON Response from Prism Central. \n %s', md_json)
    md_response.raise_for_status()
    logger.info('Successfully called Prism Central API')
    ssvm_uuid = md_json["entities"][-1]["metadata"]["uuid"]
    try:
        ssvm_project = md_json["entities"][-1]["metadata"]["project_reference"]["name"]
    except KeyError:
        ssvm_project = ''
    try:
        ssvm_owner = md_json["entities"][-1]["metadata"]["owner_reference"]["name"]
    except KeyError:
        ssvm_owner = ''

    logger.debug('UUID=%s|PROJECT=%s|OWNER=%s', ssvm_uuid, ssvm_project, ssvm_owner)
    logger.info('Obtained metadata from Prism Central.')

    # Mount and Enable Nutanix Guest Tools via Prism Element
    headers = {'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Authorization': f'Basic {ntx_pe_auth}'}
    ngt_mount_response = requests.post(
        f'{ntx_pe_url}/vms/{ssvm_uuid}/guest_tools/mount',
        headers=headers,
        timeout=prism_timeout,
        verify=False)
    logger.debug('JSON Response from Prism Element for mounting NGT \n %s',
    ngt_mount_response.json())
    ngt_mount_response.raise_for_status()
    logger.info('Successfully called Prism Element API to mount NGT')
    data = {
        'vmUuid': f'{ssvm_uuid}',
        'enabled': 'true',
        'applications': {
            "file_level_restore": "true",
            "vss_snapshot": "true"}}
    ngt_enable_response = requests.post(
        f'{ntx_pe_url}/vms/{ssvm_uuid}/guest_tools/',
        headers=headers,
        data=json.dumps(data),
        timeout=prism_timeout,
        verify=False)
    logger.debug('JSON Response from Prism Element for enabling NGT \n %s',
    ngt_enable_response.json())
    ngt_enable_response.raise_for_status()
    logger.info('Successfully called Prism Element API to enable NGT')
    sleep(5)

    # Join VM to the Active Directory Domain
    if script_os.upper() == 'LINUX':
        ad_join_cmd = (
            f'echo "{ad_bind_password}" | realm join {ad_fqdn} '
            f'-U {ad_bind_user}'
        )
        ENABLE_SSSD_CMD = (
            'systemctl enable sssd && '
            'sed -i "s/use_fully_qualified_names = True/use_fully_qualified_names = False/" '
            '/etc/sssd/sssd.conf'
        )
        adminaccess_cmd = (
            f'realm deny --all && '
            f'realm permit -g "{ad_domain}\\{linux_admins}" && '
            f'echo "%{linux_admins} ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers'
        )
        if ssvm_project and ssvm_owner:
            useraccess_cmd = (
                f'realm permit -g "{ad_domain}\\{ssvm_project}" && '
                f'echo "{ssvm_owner[:ssvm_owner.rfind("@")]} ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers'
                )
        with open(log_file, 'a') as _lf:
            if not subprocess.run(
                f'{ad_join_cmd}',
                shell=True,
                stdout=_lf,
                stderr=_lf).returncode:
                logger.info('Joined VM %s to the %s AD Domain', script_host, ad_domain)
            else:
                logger.error('Failed to join VM %s to the %s AD Domain',
                script_host, config['active_directory']['ad_domain'])
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
    if script_os.upper() == 'WINDOWS':
        ad_join_cmd = (
            f'netdom join {script_host} '
            f'/domain:{ad_fqdn} '
            f'/ud:{ad_domain}\\{ad_bind_user} '
            f'/pd:"{ad_bind_password}"'
        )
        adminaccess_cmd = (
            f'net localgroup Administrators '
            f'{ad_domain}\\{windows_admins} /ADD'
            )
        if ssvm_project and ssvm_owner:
            useraccess_cmd = (
                f'net localgroup "Remote Desktop Users" '
                f'{ad_domain}\\{ssvm_project} /ADD && '
                f'net localgroup Administrators '
                f'{ad_domain}\\{ssvm_owner[:ssvm_owner.rfind("@")]} /ADD'
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
            if not subprocess.run('shutdown /r /t 5',
                shell=True,
                stdout=_lf,
                stderr=_lf).returncode:
                logger.info('Restarting host %s.', script_host)
            else:
                logger.error('Failed to trigger restart for %s.', script_host)
except Exception:
    logger.exception('Encountered unhandled exception')
finally:
    # Cleanup
    if Path(cred_file).exists():
        Path(cred_file).unlink()

# Cloudbase-init exit for Windows to prevent re-execution upon boot.
if script_os.upper() == 'WINDOWS':
    sys.exit(1001)
