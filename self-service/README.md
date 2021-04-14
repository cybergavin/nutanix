- Nutanix Self-Service VM Provisioning Customization when using Active Directory as the IdP for access to the VM
- Supports environments with a single Prism Central managing a single Nutanix cluster
- Tested Environment: 
  - Nutanix: AOS 5.15.4/AHV 20190916.360/Prism Central pc.2021.1.0.1 - Guest VMs: Oracle Linux 8, Red Hat Enterprise Linux 8 and Windows Server 2019


## Application Listing

├ ── ntx_ssvm_customize.py

├ ── ntx_ssvm_customize.cfg

└ ── ntx_ssvm_customize.cred

### ntx_ssvm_customize.py
This script customizes a Linux or Windows VM upon self-service provisioning
by doing the following:
1. Obtains metadata (e.g. project, owner) about the VM.
2. Updates the VM's category (for pre-provisioned Policies)
3. Renames the VM to ensure uniqueness across (but, not within) projects.
4. Mounts and enables Nutanix Guest Tools on the VM.
5. Joins the VM to the specified Active Directory Domain.
6. Provisions standard SSH/RDP access (unprivileged) to the user's Project team.
7. Provisions privileged access (sudo/Administrator) to the user/owner.

When done, the user/owner may directly access the VM via SSH or RDP using 
their Active Directory domain account.

### ntx_ssvm_customize.cfg
This is the configuration file used by the above script.

### ntx_ssvm_customize.cred
This is the credential file used by the script.
Replace the values within <> and including <> with actual values.
The script deletes the credential file upon completion.

**DO NOT commit this file to source code management if you add credentials to it.**
**Upon standardization of an Enterprise Vault, it is recommended to fetch these credentials from the vault at runtime**


All the above files must be burned into a VM template and configured to be executed
by cloud-init (Linux) or cloudbase-init(Windows).