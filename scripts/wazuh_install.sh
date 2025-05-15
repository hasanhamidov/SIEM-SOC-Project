#!/bin/bash
# Example script to install Wazuh on Ubuntu Server
echo "Installing Wazuh 4.11.2..."
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
apt-get update
apt-get install wazuh-manager wazuh-indexer wazuh-dashboard -y
systemctl enable wazuh-manager wazuh-indexer wazuh-dashboard
systemctl start wazuh-manager wazuh-indexer wazuh-dashboard
echo "Wazuh installed. Access dashboard at https://192.168.10.1:443"