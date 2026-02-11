#!/bin/bash

retry() {
    for i in {1..3}; do
        echo "Attempt $i: $2"
        if $1; then
            return 0
        fi
        [ $i -lt 3 ] && sleep 5
    done
    echo "Failed after 3 attempts: $2"
    exit 1
}

retry "subscription-manager clean"
retry "curl -k -L https://${SATELLITE_URL}/pub/katello-server-ca.crt -o /etc/pki/ca-trust/source/anchors/${SATELLITE_URL}.ca.crt"
retry "update-ca-trust"
KATELLO_INSTALLED=$(rpm -qa | grep -c katello)
if [ $KATELLO_INSTALLED -eq 0 ]; then
  retry "rpm -Uhv https://${SATELLITE_URL}/pub/katello-ca-consumer-latest.noarch.rpm"
fi
subscription-manager status
if [ $? -ne 0 ]; then
    retry "subscription-manager register --org=${SATELLITE_ORG} --activationkey=${SATELLITE_ACTIVATIONKEY}"
fi
retry "dnf install -y python3-pip python3-libsemanage"

if [ ! -f /home/rhel/.ssh/id_rsa ]; then
  su rhel -c 'ssh-keygen -f /home/rhel/.ssh/id_rsa -q -N ""'
fi
nmcli connection add type ethernet con-name enp2s0 ifname enp2s0 ipv4.addresses 192.168.1.10/24 ipv4.method manual connection.autoconnect yes
nmcli connection up enp2s0
echo "192.168.1.10 control.lab control controller" >> /etc/hosts
# echo "192.168.1.11 podman.lab podman" >> /etc/hosts

# Create an inventory file for this environment
tee /tmp/inventory << EOF

[windowssrv]
windows ansible_host=windows ansible_user=Administrator ansible_password=Ansible123! ansible_connection=winrm ansible_port=5986 ansible_winrm_scheme=https ansible_winrm_transport=credssp ansible_winrm_server_cert_validation=ignore
# windows ansible_host=windows ansible_user=Administrator ansible_password=Ansible123! ansible_connection=winrm ansible_port=5986 ansible_winrm_scheme=https ansible_winrm_transport=credssp ansible_winrm_server_cert_validation=ignore ansible_become=true ansible_become_method=runas ansible_become_user=Administrator ansible_become_password=Ansible123!

[all:vars]
ansible_user = rhel
ansible_password = ansible123!
ansible_ssh_common_args='-o StrictHostKeyChecking=no'
ansible_python_interpreter=/usr/bin/python3

EOF
# sudo chown rhel:rhel /tmp/inventory

cat <<EOF | tee /tmp/track-vars.yml
---
# config vars
controller_hostname: localhost
controller_validate_certs: false
ansible_python_interpreter: /usr/bin/python3
controller_ee: Windows_ee
student_user: student
student_password: learn_ansible
controller_admin_user: admin
controller_admin_password: "ansible123!"
host_key_checking: false
custom_facts_dir: "/etc/ansible/facts.d"
custom_facts_file: custom_facts.fact
admin_username: admin
admin_password: Ansible123!
repo_user: rhel
default_tag_name: "0.0.1"
lab_organization: ACME

EOF

git config --global user.email "student@redhat.com"
git config --global user.name "student"

# Gitea setup playbook 
cat <<EOF | tee /tmp/git-setup.yml
---
# Gitea config
- name: Configure Git and Gitea repository
  hosts: localhost
  gather_facts: false
  connection: local
  tags:
    - gitea-config
  vars:
    source_repo_url: "https://github.com/amoyament/aap_and_activedirectory.git"
    student_password: 'learn_ansible'
    student_user: 'student'
  tasks:
    - name: Wait for Gitea to be ready
      ansible.builtin.uri:
        url: http://gitea:3000/api/v1/version
        method: GET
        status_code: 200
      register: gitea_ready
      until: gitea_ready.status == 200
      delay: 5
      retries: 12

    - name: Migrate source repository to Gitea
      ansible.builtin.uri:
        url: http://gitea:3000/api/v1/repos/migrate
        method: POST
        body_format: json
        body:
          clone_addr: "{{ source_repo_url }}"
          repo_name: aap_active_directory
          private: false
        force_basic_auth: true
        url_password: "{{ student_password }}"
        url_username: "{{ student_user }}"
        status_code: [201, 409] # 201 = Created, 409 = Already exists

    - name: Store repo credentials in git-creds file
      ansible.builtin.copy:
        dest: /tmp/git-creds
        mode: 0644
        content: "http://{{ student_user }}:{{ student_password }}@gitea:3000"

    - name: Configure global git settings using shell commands
      ansible.builtin.command: "{{ item }}"
      loop:
        - git config --global init.defaultBranch main
        - git config --global credential.helper 'store --file /tmp/git-creds'
        - git config --global --add safe.directory /tmp/workshop_project
        - git config --global user.name "{{ student_user }}"
        - git config --global user.email "{{ student_user }}@redhat.com"
EOF

# # Execute the setup playbooks
echo "=== Running Git/Gitea Setup ==="
ANSIBLE_COLLECTIONS_PATH=/tmp/ansible-automation-platform-containerized-setup-bundle-2.5-9-x86_64/collections/:/root/.ansible/collections/ansible_collections/ ansible-playbook -e @/tmp/track-vars.yml -i /tmp/inventory /tmp/git-setup.yml

# Ensure Python WinRM dependencies on control
if ! command -v pip3 >/dev/null 2>&1; then
  dnf -y install python3-pip || yum -y install python3-pip || true
fi
python3 -m pip install --upgrade pip || true
python3 -m pip install 'pywinrm[credssp]' requests-credssp requests-ntlm || true

ansible-galaxy collection install ansible.windows microsoft.ad || true

cat <<'EOF' | tee /tmp/windows-setup.yml
---
- name: Push and execute windows-setup.ps1 on Windows
  hosts: windowssrv
  gather_facts: false
  tasks:
    - name: Ensure WinRM service is running
      ansible.windows.win_service:
        name: WinRM
        state: started
        start_mode: auto

    - name: Enable PowerShell remoting (idempotent)
      ansible.windows.win_shell: |
        try { Enable-PSRemoting -Force -SkipNetworkProfileCheck } catch { }
      args:
        executable: powershell.exe
      changed_when: false
      failed_when: false

    - name: Ensure IIS features are present
      ansible.windows.win_feature:
        name:
          - Web-Server
          - Web-Mgmt-Console
        state: present
        include_management_tools: true

    - name: Create IIS landing page
      ansible.windows.win_copy:
        dest: C:\\inetpub\\wwwroot\\index.html
        content: |
          <!DOCTYPE html>
          <html>
          <head>
              <title>Windows AD Lab</title>
          </head>
          <body>
              <h1>Windows AD Domain Controller</h1>
              <p>This is the Windows AD domain controller for the lab.</p>
          </body>
          </html>

    - name: Disable Server Manager auto-start at logon (policy, all users)
      ansible.windows.win_regedit:
        path: HKLM:\SOFTWARE\Policies\Microsoft\Windows\Server\ServerManager
        name: DoNotOpenAtLogon
        data: 1
        type: dword
        state: present

    - name: Ensure AD DS feature is present
      ansible.windows.win_feature:
        name: AD-Domain-Services
        include_management_tools: true
        state: present

    - name: Install Chocolatey
      ansible.windows.win_shell: |
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
      args:
        executable: powershell.exe

    - name: Execute slmgr /rearm 
      ansible.windows.win_shell: cscript.exe //B //NoLogo C:\Windows\System32\slmgr.vbs /rearm
      register: slmgr_result

    - name: Reboot after Chocolatey/slmgr setup
      ansible.windows.win_reboot:
        msg: "Reboot to finalize Chocolatey/slmgr setup"
        pre_reboot_delay: 5

    - name: Set MapsBroker to manual and stopped (silence Server Manager)
      ansible.windows.win_service:
        name: MapsBroker
        start_mode: manual
        state: stopped

    - name: Install Microsoft Edge via Chocolatey (with retries)
      ansible.windows.win_shell: choco install microsoft-edge -y --no-progress
      args:
        executable: powershell.exe
      register: edge_install
      retries: 3
      delay: 20
      until: edge_install.rc == 0

    - name: Verify Edge installed
      ansible.windows.win_stat:
        path: C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe
      register: edge_bin

    - name: Fail if Edge not installed
      ansible.builtin.fail:
        msg: 'Edge did not install; check Chocolatey logs on the VM'
      when: not edge_bin.stat.exists
EOF

echo "=== Running Windows set up ==="
ANSIBLE_COLLECTIONS_PATH=/tmp/ansible-automation-platform-containerized-setup-bundle-2.5-9-x86_64/collections/:/root/.ansible/collections/ansible_collections/ ansible-playbook -e @/tmp/track-vars.yml -i /tmp/inventory /tmp/windows-setup.yml -vv

############################ CONTROLLER CONFIG

cat <<EOF | tee /tmp/controller-setup.yml
## Controller setup
- name: Controller config for Windows Getting Started
  hosts: localhost
  gather_facts: true
    
  tasks:
    - name: Add Instruqt Windows EE
      ansible.controller.execution_environment:
        name: "{{ controller_ee }}"
        image: "quay.io/nmartins/windows_ee"
        pull: missing
        state: present
        controller_host: "https://localhost"
        controller_username: "{{ controller_admin_user }}"
        controller_password: "{{ controller_admin_password }}"
        validate_certs: "{{ controller_validate_certs }}"
      tags:
        - controller-config
        - controller-ees 
        
    - name: Create Inventory
      ansible.controller.inventory:
       name: "Servers"
       description: "Our Server environment"
       organization: Default
       state: present
       controller_host: "https://localhost"
       controller_username: "{{ controller_admin_user }}"
       controller_password: "{{ controller_admin_password }}"
       validate_certs: false

    - name: Add host to inventory
      ansible.controller.host:
        name: "windows"
        inventory: "Servers" 
        state: present
        controller_host: "https://localhost"
        controller_username: "{{ controller_admin_user }}"
        controller_password: "{{ controller_admin_password }}"
        validate_certs: false

    - name: Create group with extra vars
      ansible.controller.group:
        name: "Windows_Servers"
        inventory: "Servers"
        hosts:
          windows
        state: present
        variables:
          ansible_connection: winrm
          ansible_port: 5986
          ansible_winrm_server_cert_validation: ignore
          ansible_winrm_transport: credssp
        controller_host: "https://localhost"
        controller_username: "{{ controller_admin_user }}"
        controller_password: "{{ controller_admin_password }}"
        validate_certs: false
      register: inv_group
 
    - name: Add machine credential
      ansible.controller.credential:
       name: "Windows Host"
       credential_type: Machine
       organization: Default
       inputs:
        username: Administrator
        password: "{{ admin_password }}" 
       state: present
       controller_host: "https://localhost"
       controller_username: "{{ controller_admin_user }}"
       controller_password: "{{ controller_admin_password }}"
       validate_certs: false

    - name: Add project
      ansible.controller.project:
       name: "Active-Directory AAP"
       description: "Active Directory Management"
       organization: "Default"
       scm_url: http://gitea:3000/student/aap_active_directory.git
       scm_type: "git"
       scm_branch: "main"
       scm_clean: true
       scm_update_on_launch: true
       state: present
       controller_host: "https://localhost"
       controller_username: "{{ controller_admin_user }}"
       controller_password: "{{ controller_admin_password }}"
       validate_certs: false

EOF

echo "=== Running Controller set up ==="
ANSIBLE_COLLECTIONS_PATH=/root/.ansible/collections/ansible_collections/ ansible-playbook -e @/tmp/track-vars.yml -i /tmp/inventory /tmp/controller-setup.yml
