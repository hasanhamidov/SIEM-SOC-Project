Setup Guide for SIEM/SOC Environment
Author: Hamidov HasanDate: May 2025
Overview
This guide provides detailed instructions to set up a Security Information and Event Management (SIEM) and Security Operations Center (SOC) environment, as described in the Lab_Report.md. The setup includes configuring virtual machines (VMs) using VMware Workstation, establishing a hybrid network, deploying Wazuh and Splunk for monitoring, installing vulnerable applications on target machines, and preparing an attacker machine for simulations. By following this guide, you can replicate the environment used for attack simulation and log analysis in the SIEM-SOC-Project.
Table of Contents

Prerequisites
Virtual Machine Setup
Network Configuration
Monitoring Server Setup (Wazuh and Splunk)
Target Machine Setup (Kali Client and Windows Client)
Attacker Machine Setup
Next Steps

Prerequisites
Before starting, ensure you have the following:

Knowledge:
Basic understanding of Windows and Linux operating systems.
Familiarity with networking concepts (e.g., IP addressing, NAT, internal networks).
Basic cybersecurity knowledge (e.g., SSH, SMB, RDP, SIEM tools).


Hardware Requirements:
A host machine with at least 32 GB RAM and 300 GB free disk space.
CPU with virtualization support (e.g., Intel VT-x or AMD-V).


Software Requirements:
VMware Workstation: Used for creating and managing VMs.
ISO Files:
Ubuntu Live Server (e.g., Ubuntu 22.04 LTS).
Kali Linux (e.g., Kali Linux 2024.1).
Windows 10 (official ISO from Microsoft).


Internet Access: Required for downloading updates, Wazuh/Splunk installers, and other dependencies.


Tools:
Wazuh (version 4.11.2) for SIEM monitoring.
Splunk for log analysis.
Metasploit Framework (pre-installed on Kali Linux) for attack simulation.



Virtual Machine Setup
This section covers the creation of four virtual machines (VMs) required for the lab environment.
Step 1: Create Virtual Machines

Install VMware Workstation:

Download and install VMware Workstation from the official website (https://www.vmware.com/products/workstation-pro.html).
Ensure your system meets the requirements (e.g., 32 GB RAM, 300 GB disk space).


Create VMs:

Open VMware Workstation and create the following VMs with these specifications:



Role
OS
RAM
Disk Space
Network Adapter



Ubuntu Server
Ubuntu Live Server
8 GB
80 GB
VMnet10 + NAT


Kali Client
Kali Linux
4 GB
60 GB
VMnet10


Windows Client
Windows 10
8 GB
80 GB
VMnet10


Attacker
Kali Linux
4 GB
60 GB
VMnet10



Steps for Each VM:

Select “New Virtual Machine” > “Typical (recommended)” > Choose the respective ISO file.
Allocate the specified RAM and disk space.
For network adapters:
Ubuntu Server: Add two adapters: Custom (VMnet10) and NAT.
Kali Client, Windows Client, Attacker: Add one adapter: Custom (VMnet10).






Install Operating Systems:

Power on each VM and follow the installation prompts for Ubuntu Live Server, Kali Linux, and Windows 10.
For Ubuntu Server, choose minimal installation and enable SSH during setup.
For Kali Linux, select the default graphical install and enable SSH.
For Windows 10, complete the setup and enable Remote Desktop Protocol (RDP).




Network Configuration
This section configures the network for all VMs to communicate internally and access the internet.
Step 1: Configure VMnet10 Network

In VMware Workstation, go to Edit > Virtual Network Editor.
Add a custom network:
Select VMnet10.
Set type to “Host-only” (isolated network).
Subnet: 192.168.10.0/24.
Disable “Connect a host virtual adapter” and “Use local DHCP service”.


Apply changes.

Step 2: Assign Static IPs

Assign static IPs to each VM on the VMnet10 network:
Ubuntu Server:
Interface: ens33 (VMnet10)
IP: 192.168.10.1
Netmask: 255.255.255.0
Edit /etc/netplan/00-installer-config.yaml:network:
  ethernets:
    ens33:
      dhcp4: no
      addresses: [192.168.10.1/24]
    ens34:
      dhcp4: yes
  version: 2


Apply: sudo netplan apply


Kali Client:
Interface: eth0 (VMnet10)
IP: 192.168.10.10
Edit /etc/network/interfaces:auto eth0
iface eth0 inet static
  address 192.168.10.10
  netmask 255.255.255.0


Restart networking: sudo systemctl restart networking


Windows Client:
IP: 192.168.10.20
Go to Network Settings > Adapter Properties > IPv4 Settings:
IP Address: 192.168.10.20
Subnet Mask: 255.255.255.0




Attacker:
IP: 192.168.10.30
Same process as Kali Client, but set IP to 192.168.10.30.





Step 3: Configure Ubuntu Server’s NAT Interface

The Ubuntu Server’s second adapter (ens34) uses NAT for internet access.
IP is assigned via DHCP (e.g., 192.168.75.128 in the lab).
Verify internet access: ping google.com.

Step 4: Test Connectivity

From each VM, ping the others to confirm connectivity on VMnet10:
From Ubuntu Server: ping 192.168.10.10, ping 192.168.10.20, ping 192.168.10.30.
From Kali Client: ping 192.168.10.1, etc.




Monitoring Server Setup (Wazuh and Splunk)
This section sets up the Ubuntu Server (192.168.10.1) as the monitoring server with Wazuh and Splunk.
Step 1: Install Wazuh (v4.11.2)

Update the System:
sudo apt update && sudo apt upgrade -y


Install Dependencies:
sudo apt install -y curl apt-transport-https lsb-release gnupg2


Add Wazuh Repository:
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update


Install Wazuh Components:

Install Wazuh Indexer, Manager, and Dashboard:sudo apt install -y wazuh-indexer wazuh-manager wazuh-dashboard


Start services:sudo systemctl enable --now wazuh-indexer
sudo systemctl enable --now wazuh-manager
sudo systemctl enable --now wazuh-dashboard




Configure Wazuh:

Wazuh Dashboard will be accessible at https://192.168.10.1:443.
Default credentials: Username admin, Password (auto-generated, check /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml).
See scripts/wazuh_install.sh in the repository for a sample installation script.



Step 2: Install Splunk

Download Splunk:

Download Splunk Enterprise (free version) from https://www.splunk.com/en_us/download.html.
Example command (adjust version as needed):wget -O splunk-9.0.4-linux-2.6-amd64.deb 'https://www.splunk.com/bin/splunk/DownloadActivityServlet?architecture=x86_64&platform=linux&version=9.0.4&product=splunk&filename=splunk-9.0.4-linux-2.6-amd64.deb&wget=true'




Install Splunk:
sudo dpkg -i splunk-9.0.4-linux-2.6-amd64.deb


Start Splunk:
sudo /opt/splunk/bin/splunk start


Accept the license and set an admin password when prompted.


Enable Splunk on Boot:
sudo /opt/splunk/bin/splunk enable boot-start


Access Splunk:

Splunk will be accessible at http://192.168.10.1:8000.
Log in with the admin password you set.


Sample Configuration:

See scripts/splunk_config.conf for a sample Splunk configuration.



Target Machine Setup (Kali Client and Windows Client)
This section configures the Kali Client (192.168.10.10) and Windows Client (192.168.10.20) as target machines with vulnerable applications and SIEM agents.
Step 1: Kali Client Setup

Install Vulnerable Applications:

SSH:sudo apt update
sudo apt install -y openssh-server
sudo systemctl enable --now ssh


Create a vulnerable account:sudo useradd -m -p $(openssl passwd -1 password) admin




SMB:sudo apt install -y samba
sudo smbpasswd -a admin


Set SMB password to password.
Configure /etc/samba/smb.conf to allow guest access (for vulnerability).


HTTP Apache:sudo apt install -y apache2
sudo systemctl enable --now apache2


Intentionally misconfigure Apache (e.g., allow directory listing by editing /etc/apache2/apache2.conf).




Install Wazuh Agent:

Download and install the Wazuh agent:curl -so wazuh-agent.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.11.2-1_amd64.deb
sudo WAZUH_MANAGER="192.168.10.1" dpkg -i wazuh-agent.deb
sudo systemctl enable --now wazuh-agent




Install Splunk Universal Forwarder:

Download the Splunk Universal Forwarder:wget -O splunkforwarder-9.0.4-linux-2.6-amd64.deb 'https://www.splunk.com/bin/splunk/DownloadActivityServlet?architecture=x86_64&platform=linux&version=9.0.4&product=universalforwarder&filename=splunkforwarder-9.0.4-linux-2.6-amd64.deb&wget=true'


Install:sudo dpkg -i splunkforwarder-9.0.4-linux-2.6-amd64.deb


Configure to forward to Splunk server:sudo /opt/splunkforwarder/bin/splunk add forward-server 192.168.10.1:9997
sudo /opt/splunkforwarder/bin/splunk start





Step 2: Windows Client Setup

Install Vulnerable Applications:

SSH:
Install OpenSSH Server via Settings > Apps > Optional Features > Add a feature > OpenSSH Server.
Start the service: net start sshd.
Create a vulnerable account:
Open Command Prompt as Administrator:net user admin password /add
net localgroup Administrators admin /add






RDP:
Enable RDP: Settings > System > Remote Desktop > Enable Remote Desktop.
Use the admin/password account for access.


SMB:
Enable SMB: Settings > Apps > Optional Features > Add a feature > SMB 1.0/CIFS File Sharing Support.
Share a folder with guest access for vulnerability.




Install Wazuh Agent:

Download the Wazuh agent for Windows from https://packages.wazuh.com/4.x/windows/wazuh-agent-4.11.2-1.msi.
Install via GUI or command line:msiexec.exe /i wazuh-agent-4.11.2-1.msi /q WAZUH_MANAGER="192.168.10.1"


Start the service:net start wazuh




Install Splunk Universal Forwarder:

Download the Splunk Universal Forwarder for Windows from https://www.splunk.com/en_us/download/universal-forwarder.html.
Install via GUI or command line:msiexec.exe /i splunkforwarder-9.0.4-x64-release.msi RECEIVING_INDEXER="192.168.10.1:9997" /quiet


Start the service:net start SplunkForwarder





Attacker Machine Setup
This section configures the Attacker machine (192.168.10.30, Kali Linux) for simulating attacks.

Update Kali Linux:
sudo apt update && sudo apt upgrade -y


Install Metasploit Framework:

Metasploit is pre-installed on Kali Linux. Verify:msfconsole


If not installed:sudo apt install -y metasploit-framework




Prepare Wordlist:

Use the default Metasploit wordlist: /usr/share/wordlists/metasploit/user.txt.
Optionally, create a custom wordlist with admin and password for testing.


Sample Attack Script:

See scripts/metasploit_attack.ms in the repository for a sample Metasploit script to perform brute-force attacks on SSH, SMB, and RDP.




Next Steps

Verify Setup:
Ensure Wazuh Dashboard (https://192.168.10.1:443) shows agents from Kali Client and Windows Client.
Verify Splunk (http://192.168.10.1:8000) receives logs from both target machines.


Perform Attacks:
Use the Attacker machine to simulate attacks (e.g., brute-force SSH, SMB, RDP) as described in Lab_Report.md.


Analyze Logs:
Check Wazuh alerts and Splunk logs for attack detections, as shown in the lab report.



For detailed results and attack simulations, refer to Lab_Report.md. Additional screenshots are in the docs/screenshots/ folder.
