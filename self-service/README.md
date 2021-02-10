# Nutanix Self-Service VM Provisioning Customization

## Application Listing

├ ── ntx_ssvm_customize.py

├ ── ntx_ssvm_customize.cfg

└ ── ntx_ssvm_customize.cred

### ntx_ssvm_customize.py
This script customizes a Linux or Windows VM upon self-service provisioning
by doing the following:
1. Obtaining metadata (e.g. project, owner) about the VM.
2. Mounting and Enabling Nutanix Guest Tools on the VM.
3. Joining the VM to a specified Active Directory Domain.
4. Provisioning standard SSH/RDP access (unprivileged) to the user's Project team.
5. Provisioning privileged access (sudo/Administrator) to the user/owner.

When done, the user/owner may directly access the VM via SSH or RDP using 
their Active Directory domain account.

### ntx_ssvm_customize.cfg
This is the configuration file used by the above script.

### ntx_ssvm_customize.cred
This is the credential file used by the script.
Replace the values within <> and including <> with actual values.
The script deletes the credential file upon completion.

**DO NOT commit this file to source code management if you add credentials to it.**
**It is recommended to fetch these credentials from a vault at runtime.** . You will have to 
modify the python script.


All the above files must be burned into a VM template and configured to be executed
by cloud-init (Linux) or cloudbase-init(Windows).
