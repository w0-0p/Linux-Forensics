# 01 Initial Access
# 02 Execution
- 
- keygen
1. [Remote Code (or Command) Execution (RCE)](#rce)
2. [excetution of malicious service](#malicious-service)

## RCE
### CVE-2021-44228 (Log4j)

## Malicious Service

# 03 Persistence
Persistence:

collection-cron-folder-list.txt

collection-cron-tab-list.txt

collection-service_status.txt

collection-systemctl_service_status.txt

collection-cron-folder.tar.gz

collection-persistence-systemdlist.txt  

collection-systemctl_all.txt

keygen ?

add image from Computer Forensic class (schema of related techniques)


1. [Account Creation (User or Root)](#account-creation-user-or-root)
2. [SSH Keys](#ssh-keys) 
4. [Cron Jobs](#cron-jobs)
5. [Systemd Services and Timers](#systemd-services-and-timers)
6. [Shell Configuration Modification](#shell-configuration-modification)
7. [Dynamic Linker Hijacking](#dynamic-linker)
8. [Shared object Library](#shared-object-library)
9. [SUID](#suid)
10. [rc.common/rc.local]
11. [Systemd Services](#systemd-services)
12. [Trap](#trap)
13. [Startup file](#startup-file)
14. [System Call](#system-call)
15. [MOTD Backdooring]
16. [APT Backdooring]
17. [Git Backdooring]
18. [Config](#config)
19. [Backdooring OpenVPN]
20. [Rootkits] (#rootkits)
21. UDEV **to do** (see book)
22. [GTFOBins Reverse Shell](#gtfobins-reverse-shell)
23. [Web Shell](#web-shell)
CHECK PANIX tool for additionnal persistence techniques


## Account Creation (User or Root)

### Check passwd file.
Ubuntu, Debian, CentOS, Fedora:
/etc/passwd

FreeBSD:
/etc/master.passwd

#### Check it with Velociraptor
Default artifact: Linux.Sys.Users

### Post-process Notebook query (example)
```sql
/*
# Linux.Sys.Users
*/
SELECT * FROM source(artifact="Linux.Sys.Users")
WHERE NOT Shell =~ "nologin"
and NOT Shell =~"false"
LIMIT 50
```

## SSH Keys

### Authorized Keys

Check authorized_keys file.

/home/\<username>/.ssh/authorized_keys

#### Check it with Velociraptor:
Default artifact: Linux.Ssh.AuthorizedKeys

### Private Keys

Check if private keys are encrypted in directory.
--> if not encrypted, it is recommended to revoque 
these private keys.

/home/\<username>/.ssh

#### Check it with Velociraptor:
Default artifact: Linux.Ssh.PrivateKeys

## Cron Jobs

Check cron tab files.

System-level:
- /etc/crontab
- /etc/cron.d/*
- /etc/cron.{hourly,daily,weekly,monthly}/*
- /var/spool/cron/crontab/*

User-level:
- ~/var/spool/cron/crontabs/

#### Check it with Velociraptor:

Default artifact: Linux.Sys.Crontab
Or with custom artifact: Linux.Collection.Autoruns

## Systemd Services and Timers
Creating a Custom systemd Service for persistence.

Check service files: 
/etc/systemd/system/*.service

Check timer files:
/etc/systemd/system/*.timer

#### Check it with Velociraptor:

Default artifact: Linux.Sys.Services

### Custom Notebook query
```sql
/*
# System Timers
*/
LET services = SELECT Stdout FROM execve(argv=['systemctl', 'list-units',  '--type=timer'])

LET all_services = SELECT grok(grok="%{NOTSPACE:Unit}%{SPACE}%{NOTSPACE:Load}%{SPACE}%{NOTSPACE:Active}%{SPACE}%{NOTSPACE:Sub}%{SPACE}%{GREEDYDATA:Description}", data=Line) AS Parsed
FROM parse_lines(accessor="data", filename=services.Stdout)

SELECT * FROM foreach(row=all_services, column="Parsed") WHERE Unit =~ ".timer"
```

## Shell Configuration Modification

| Files | Working |
|-------|---------|
| /etc/bash.bashrc | systemwide files executed at the start of interactive shell |
| /etc/bash_logout | Systemwide files executed when we terminate the shell |
| ~/.bashrc	| Widly exploited user specific startup script executed at the start of shell |
| ~/.bash_profile, ~/.bash_login, ~/.profile | User specific files , but which found first are executed first |
| ~.bash_logout | User specific files, executed when shell session closes |
| ~/.bash_logout | User-specific clean up script at the end of the session |
| /etc/profile | Systemwide files executed at the start of login shells |
| /etc/profile.d | all the .sh files are executed at the start of login shells |

#### Check it with Velociraptor:

Inspect Bash logout files: Linux.System.BashLogout
Search for files: Linux.Search.FileFinder

## Shared object Library
To Check:
- Env virable LD_PRELOAD in /etc/profile or a script in /etc/profile.d/
- File /etc/ld.so.preload
- Otherwise, inspect individual processes
- Use tools like chkrootkit and rkhunter to scan for rootkits and suspicious files.

## SUID
#### Check it with Velociraptor:
Linux.Sys.SUID
Linux.Detection.AnomalousFiles
Exchange.Linux.Detection.IncorrectPermissions

## rc.common
Execute a command at the end of the boot process.
To check: File /etc/rc.local
#### Check it with Velociraptor:
Linux.Search.FileFinder

## Startup file
Commonly targeted files include ~/.bashrc, ~/.profile, or ~/.bash_profile

System-wide
Check /etc/init.d/, /etc/rc.d/, /etc/systemd/system/

User-specific
Check ~/.config/autostart/, ~/.config/ (under various subdirectories)

## System Call
### Use Emulate/Implement System Call in User-Space
To Do
### Alternate System Calls
To Do
### Fudging Around Parameters
To Do

## MOTD Backdooring
File in /etc/update-motd.d/

## APT Backdooring
APT hook files in /etc/apt/apt.conf.d/

## Git Backdooring
### Hook
Hook files in /.git/hooks/
### Config
Config file in /.git/config (global) and in each project in ~/.git/config

## PAM
Check files in /lib64/security/

## GTFOBins Reverse Shell
See https://gtfobins.github.io/#+shell

## Web shell
### Apache Tomcat webserver - vulnerable manager application
https://github.com/mgeeky/tomcatWarDeployer  
malicious war file dropped in /webapps/ dir.  
sh spawned by a java proces




[def]: #systemd-timersw

# 04 Privilege Escalation
1. [Processes Privilege Escalation](#processes-privilege-escalation)
2. [Linux Kernel Vulnerability](#linux-kernel-vulnerability)
3. 

## Processes Privilege Escalation
**Detection with Velociraptor**  
Artifact: Exchange.Linux.PrivilegeEscalationDetection
### CVE-2021-4034
Polkit vulnerability, with `pkexec` commmand.  
**Detection with Velociraptor**  
Artifact: Exchange.Linux.Detection.CVE20214034

## Linux Kernel Vulnerability
Detection:
- sunlight?
- RAM dump
- Linux Commands (see github repo)
### CVE-2022-0847 (Dirty Pipe)
Detection: wget https://github.com/airbus-cert/dirtypipe-ebpf_detection/releases/download/v0.1/dirtypipe_detection
### CVE-2022-2588
**Detection with Velociraptor**  
Search for suspect users (with pwd hash in /etc/passwd)  
Artifact: Linux.Sys.User
### CVE-2023-2640
### CVE-2023-32629

# 05 Defense Evasion
[Hide File or Directory](#)

- process renaming
- encoding

## Hide File or Directory
## 
## 
## 
## 
## 
## 
## 
## 
## 
##
## 
## 
## 
## 
## 
## 
## 
## 
## 
## 
## 
## 
## 
## 
## 
## 
## 
## 
## 

# 06 Credential Access

1. [Read /etc/shadow](#read-etcshadow)
2. [SSH Password Spraying](#ssh-password-spraying)
3. [SSHD Sniffing with Strace](#sshd-sniffing-with-strace)
4. [PAM auth() Sniffing with bpftrace](#pam-auth-sniffing-with-bpftrace)

## Read /etc/shadow
## SSH Password Spraying
## SSHD Sniffing with Strace
## PAM auth() Sniffing with bpftrace

# 07 Discovery

# 08 Lateral Movement

## ssh key reuse
- Command Execution
Check file:  
~/.bash_history
- Logon Sessions
Check logs:  
/var/log/auth.log  
/var/log/btmp
## Processes
## Lateral Tool Transfer
Files can be transferred using native tools, such as scp, rsync, curl, sftp, and ftp. Adversaries may be able to leverage Web Services such as Dropbox or OneDrive to copy files from one machine to another via shared.

# 09 Collection

# 10 Command and Control
[C2 Implants](#c2-implants)
2. [Tunneling Tools](#tunneling-tools)
3. [Process via Proxy Chain](#process-via-proxy-chain)
4. [Non-standard HTTP/HTTPS Ports](#non-standard-httphttps-ports)
5. [Reverse Shells](#reverse-shells)
6. [Upgrade Reverse Shell to PTY Shell](#upgrade-reverse-shell-to-pty-shell)

## C2 Implants  
## Tunneling Tools
## Process via Proxy Chain
## Non-standard HTTP/HTTPS Ports
## Reverse Shells
## Upgrade Reverse Shell to PTY Shell

# 11 Exfiltration
[GTFOBins File Upload](#gtfobins-file-upload)
2. [Path Traversal](path-traversal)
3. [Network File Sharing (NFS)](nfs)

## GTFOBins File Upload
https://gtfobins.github.io/#+file%20upload

## Path Traversal
For example:   
`curl -v --path-as-is http://10.7.0.10:8181/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd`

## NFS
`no_root_squash`misconfiguration:  
When `no_root_squash` is enabled, it bypasses root squashing, granting the root user on the client full root-level access to the locally mounted NFS shares from the remote NFS server.

# 12 Impact

# 13 Linux Commands - Misc.

