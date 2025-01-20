# Nxcscan
This repo hosts nxcscan, a wrapper around netexec to automate some workflows.

# Installation
```bash
python3 setup.py
source ~/.bashrc
```

# Usage
```bash
nxcscan $IP -u $USER -p $PASS -d $DOMAIN
```
```bash
┌─[kali@parrot]─[~]
└──╼ $nxcscan
usage: nxcscan.py [-h] [-u USERNAME] [-p PASSWORD] [-H HASH] [-t] [-d DOMAIN]
                  [-x] [-l]
                  target
nxcscan.py: error: the following arguments are required: target
┌─[✗]─[kali@parrot]─[~]
└──╼ $nxcscan -h
usage: nxcscan.py [-h] [-u USERNAME] [-p PASSWORD] [-H HASH] [-t] [-d DOMAIN]
                  [-x] [-l]
                  target

Helper script for running netexec variations

positional arguments:
  target                Target IP address or CIDR notation

options:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        Username for authentication
  -p PASSWORD, --password PASSWORD
                        Password for authentication
  -H HASH, --hash HASH  Hash for LDAP
  -t, -k, --ticket      Use kcache for authentication
  -d DOMAIN, --domain DOMAIN
                        Domain for authentication
  -x, --proxychains     Use proxychains
  -l, --local-auth      Use local authentication
```


# Example
```bash
➜  nxcscan 10.10.184.22/28 -u peter.turner -d hybrid.vl -p '<REDACTED>'
NXC Scans Initiated.
ftp scan completed.
ldap scan completed.
mssql scan completed.
rdp scan completed.
smb scan completed.
ssh scan completed.
vnc scan completed.
winrm scan completed.
wmi scan completed.
ftp scan completed.
smb shares scans completed.
nxc scans completed.
➜  cd nxc-output
➜  nxc-output cat *


Command run to generate this output:
nxc ftp 10.10.184.22/28 -u peter.turner -p <REDACTED> -d hybrid.vl


Command run to generate this output:
nxc ldap 10.10.184.22/28 -u peter.turner -p <REDACTED> -d hybrid.vl
SMB                      10.10.184.21    445    DC01             [*] Windows 10.0 Build 20348 x64 (name:DC01) (domain:hybrid.vl) (signing:True) (SMBv1:False)
LDAP                     10.10.184.21    389    DC01             [+] hybrid.vl\peter.turner:<REDACTED>
Running nxc against 16 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00


Command run to generate this output:
nxc mssql 10.10.184.22/28 -u peter.turner -p <REDACTED> -d hybrid.vl
Running nxc against 16 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00


Command run to generate this output:
nxc rdp 10.10.184.22/28 -u peter.turner -p <REDACTED> -d hybrid.vl
Running nxc against 16 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00


Command run to generate this output:
nxc smb 10.10.184.21 -u peter.turner -p <REDACTED> -d hybrid.vl --shares
SMB                      10.10.184.21    445    DC01             [*] Windows 10.0 Build 20348 x64 (name:DC01) (domain:hybrid.vl) (signing:True) (SMBv1:False)
SMB                      10.10.184.21    445    DC01             [+] hybrid.vl\peter.turner:<REDACTED>
SMB                      10.10.184.21    445    DC01             [*] Enumerated shares
SMB                      10.10.184.21    445    DC01             Share           Permissions     Remark
SMB                      10.10.184.21    445    DC01             -----           -----------     ------
SMB                      10.10.184.21    445    DC01             ADMIN$                          Remote Admin
SMB                      10.10.184.21    445    DC01             C$                              Default share
SMB                      10.10.184.21    445    DC01             IPC$            READ            Remote IPC
SMB                      10.10.184.21    445    DC01             NETLOGON        READ            Logon server share
SMB                      10.10.184.21    445    DC01             SYSVOL          READ            Logon server share


Command run to generate this output:
nxc smb 10.10.184.22 -u peter.turner -p <REDACTED> -d hybrid.vl --shares


Command run to generate this output:
nxc smb 10.10.184.22/28 -u peter.turner -p <REDACTED> -d hybrid.vl
SMB                      10.10.184.21    445    DC01             [*] Windows 10.0 Build 20348 x64 (name:DC01) (domain:hybrid.vl) (signing:True) (SMBv1:False)
SMB                      10.10.184.21    445    DC01             [+] hybrid.vl\peter.turner:<REDACTED>
Running nxc against 16 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00


Command run to generate this output:
nxc ssh 10.10.184.22/28 -u peter.turner -p <REDACTED> -d hybrid.vl


Command run to generate this output:
nxc vnc 10.10.184.22/28 -u peter.turner -p <REDACTED> -d hybrid.vl


Command run to generate this output:
nxc winrm 10.10.184.22/28 -u peter.turner -p <REDACTED> -d hybrid.vl
HTTP                     10.10.184.21    5985   DC01             [*] http://10.10.184.21:5985/wsman
HTTP                     10.10.184.21    5985   DC01             [-] hybrid.vl\peter.turner:<REDACTED>
Running nxc against 16 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00


Command run to generate this output:
nxc wmi 10.10.184.22/28 -u peter.turner -p <REDACTED> -d hybrid.vl
RPC                      10.10.184.21    135    DC01             [*] Windows NT 10.0 Build 20348 (name:DC01) (domain:hybrid.vl)
RPC                      10.10.184.21    135    DC01             [+] hybrid.vl\peter.turner:<REDACTED>
Running nxc against 16 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```
