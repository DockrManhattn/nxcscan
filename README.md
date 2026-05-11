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
┌─[us-dedicated-217-dhcp]─[10.10.14.8]─[dockrmanhattn@htb-x9w2rmvnb6]─[~]
└──╼ [★]$ nxcscan
usage: nxcscan.py [-h] [-log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}] [-debug] [-log] [-u USERNAME] [-p PASSWORD] [-H HASH] [-t] [-x] [-d DOMAIN] [-l] [-s SERVICES] [-o OUTPUTDIR]
                  target
nxcscan.py: error: the following arguments are required: target
┌─[us-dedicated-217-dhcp]─[10.10.14.8]─[dockrmanhattn@htb-x9w2rmvnb6]─[~]
└──╼ [★]$ nxcscan -h
usage: nxcscan.py [-h] [-log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}] [-debug] [-log] [-u USERNAME] [-p PASSWORD] [-H HASH] [-t] [-x] [-d DOMAIN] [-l] [-s SERVICES] [-o OUTPUTDIR]
                  target

Template script with configurable logging.

positional arguments:
  target                Target IP address or CIDR notation.

options:
  -h, --help            show this help message and exit
  -log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                        Set the console logging level (file logging is always DEBUG).
  -debug, -v            Shortcut for -log-level DEBUG.
  -log                  Show the last 200 lines of the log file and exit.
  -u USERNAME, --username USERNAME
                        Username for authentication.
  -p PASSWORD, --password PASSWORD
                        Password for authentication.
  -H HASH, --hash HASH  Hash for authentication.
  -t, --ticket, --use-kcache
                        Use Kerberos cache (kcache) for authentication.
  -x, --proxychains     Use proxychains when running commands.
  -d DOMAIN, --domain DOMAIN
                        Domain for authentication.
  -l, --local-auth      Use local authentication.
  -s SERVICES, --services SERVICES
                        Comma-separated list of services to discover and scan (default: smb,mssql,wmi,winrm).
  -o OUTPUTDIR, -outputdir OUTPUTDIR
                        Specify a custom base directory for the output folder. The script will create 'nxcscan' inside this path.
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
