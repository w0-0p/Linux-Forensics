# Linux Live Analysis Knowledge Base, Tips & Tricks
1. [System Infos and Settings](#system-info-and-settings)
2. [Users, User Groups and Authentication (SSH)](#users-user-groups-and-authentication-ssh)
3. [Files, Directories and Binaries](#files-directories-and-binaries)
4. [System Logs](#system-logs)
5. [Processes](#processes)
6. [Persistence, overview](#persistence-overview)
7. [Privilege Escalation, overview](#privilege-escalation-overview)
8. [Exfiltration](#exfiltration)
9. [Usefull Velociraptor artifacts](#useful-velociraptor-artifacts)

## System Infos and Settings
### Commands  
|Command|Output|
|---|---|
**System Information** 
|`#date`|Date, time, timezone|
|`#uname -a` | System hostname, OS and Kernel versions|
|`#uname -r` | Kernel version|
|`#uname -n` | System hostname|
|`#uname -m` | Kernel architecture| 
|`#cat /etc/*-release` | Distribution information
|`#cat /proc/stat \| grep btime` | System boot time  
**Users and Groups**  
|[see](#users-user-groups-and-authentication-ssh)||  
**Networking**  
|`#ifconfig -a` | Network interfaces|
|`#netstat -nalp` | Current connections, routing table, net. int. stats|
**Processes**  
|[see](#processes)||
**File system**  
|`#df -a` | File system information|
|`#mount` | File system information|
**Kernel**  
|`#cat /proc/version` | Kernel information|
|`#lsmod` | Lists installed kernel modules|

-------**Timestamps**
As always, never rely on the (default) timestamp from ls-------
## Users, User Groups and Authentication (SSH)
**`/etc/passwd`** (Users),  **`/etc/shadow`** (hashed passwords)
- new user accounts
- only `root` should have UID 0
- suspicious home directories, for example hidden: `~/.hiddendir`
- login shell (service users must have `nologin` or `false`)  
- in `/etc/shadow` check for password hashes for users without a shell

**`/etc/group`**  
- lists groups and members

**Logins**  
Search for suspicious logins or failed attempts.  
- `#w`: currently logged in users
- `#last`: last successful logins
- `#lastb`: last failed login
- `#lastlog`: list last login for all users
- `#utmpdump /var/run/utmp`: all current logins, check type (0 is not valid)
- `#utmpdump /var/log/btmp`: raw dump of btmp (possible to find pw, if a user accidentaly typed pw at the user login prompt)
- if login from a service user → check `nologin` or `false` binary integrity

**SSH Keys**  
Check for suspicious authorized keys, unprotected private keys, suspicous SSH configs, suspicious creation/modification timestamps.  
- `~/.ssh/`: private keys
- `~/.ssh/authorized_keys`: authorized keys file (check for user email address)
- `~/.ssh/known_hosts`: list of hosts accessed previously
- `/etc/ssh/ssh_config`, `/etc/ssh/ssh_config.d`, `~/.ssh/config`: ssh client config
- if a private key is not encrypted → recommended to revoque it

**Useful Velociraptor Artifacts**
- `Linux.Sys.Users`: retrieve Users
- `Linux.Users.RootUsers`: retrieve Users in *sudo* Group
- `Linux.Sys.LastUserLogin`: retrieve wtmp file content (successful logins and logouts)
- `Linux.Users.InteractiveUsers`: retrieve the interactive users (shell login)
- `Linux.Ssh.AuthorizedKeys`: retrieve authorized SSH keys
- `Linux.Ssh.PrivateKeys`: retrieve private keys + checks if encrypted or not
## Files, Directories and Binaries
Search for suspicious files, directories and creation/modification timestamps.
- suspicious Directories:  
  - tries to look like a system directory
  - hidden in system areas
  - weird permissions, attributes (immutable?), timestamp
  - comparison with duplicate VM does not match
- suspicious Files:
  - displayed type (name) not matching real file type
  - modified system binary
  - binary in strange location
  - high entropy (file is encrypted) use: https://github.com/sandflysecurity/sandfly-entropyscan
- hidden files or directories starting with `.`, `..`, `...`
- `/tmp`, `/var/tmp`, `/dev/shm`: world-writable directories (often used to drop malicious files)
- `#ls -alp`: lists element with a / at the end (allows to see empty spaces)
- `#lsattr`: list attributes of a File or Dir (see if immutable flag is set)
- `#file /path/to/file`: basic file summary
- `#ldd /path/to/binary`: **! never run `ldd` on a suspicious binary (could execute malicious code) !** lists shared objects
- `#objdump -p /path/to/binary | grep NEEDED`: lists required shared objects
- `#strings /path/to/bianary`: search for suspicious content like `listen()`, `bind()` and/or `accept()`, IP addresses, etc.
- `#find /<dir> -perm 4000`: look for suspicious *setuid* files
- `#find -nouser` `#find -nogroup`: files without assigned UID/GID (may indicate deleted user/group)

**Useful Velociraptor Artifacts**
- `Linux.Detection.AnomalousFiles`: hidden, large or SUID bit set
- `Exchange.Linux.Detection.IncorrectPermissions`: verify files/dirs and checks whether they have the expected owner, group owner and mode.
- [IDEA]: artifact to detect high entropy files (means the file is encrypted → suspicious)
## System Logs  
**Syslog**  
Check for tampered or missing logs.
- general log files under `/var/log/*`
- log files of interest for attackers (logins): `wtmp`, `lastlog`, `btmp`, `utmp`
- security/authentication related events: `auth.log`
- application specific log files under `/var/log/<application>/*`
- security relevant events: `/var/log/audit/audit.log`
 - `#ausearch --input audit.log --format <csv/text>`: export audit.log file to another format
 - `#aureport --input audit.log --login --start YYYY-MM-DD HH:mm:ss --end YYYY-MMM-DD HH:mm:ss`: generate a report of audit.log  

**Systemd Journal**
- `/var/log/journal/*`
- `/run/log/jounral/*` (volatile)
Anlaysis of Journal File Contents
- `#journalctl --file <filename>`
- `#journalctl --file system.journal -o json > sytem.journal.json`: export journal to json format (other format available)
- `#journalctl --file system.journal _SYSTEMD_UNIT=sshd.service`: Search logs from sshd.service
- `#journalctl --file user-1000.journal _TRANSPORT=stdout`: stdout logs of deamons and unit files
- `#journalctl --file user-1000.journal --verify`: If journal file contains FSS information → verify integrity
- `#journalctl --file user-1000.journal -S "YYYY-MM-DD HH:mm:ss" -U "YYYY-MM-DD HH:mm:ss"`: Search logs since (-S) until (-U)

**Sysmon for Linux**  
- not maintained, not suitable for production
- alternatives for Linux: ebpf, auditd
## Processes  
- Suspicious processes:
  - process named to look legit
  - open ports that seem odd
  - outbound connections that seem odd
  - deleted processes with open ports
  - deleted binary
- `#ps auxwf`: Check for process running from `/dev`, `/root`, `/temp`, high PID (process started manually after OS boot) process masquerading as a kthread
- `#pstree`: List a tree view of processes with parent-child relations
- `#pstree -p -s <PID>`: Process tree of a running process
- `#top`: List processes according their ressource usage
- `#htop`: List processes according their ressource usage
- `netstat -nalp`: High port or raw socket open?
- `ls -al /proc/*/fd | grep deleted`: Search for running processes spawened from a file deleted from disk (very suspicious)
- `cat /proc/<PID>/comm`: Shows the executable's name
- `cat /proc/<PID>/cmdline`: Shows the full command line that was used to start the process
- `cat /proc/<PID>/environ`: Shows environment variables that were set when the process was started
- `cat /proc/<PID>/map`: Shows the memory map
- `cat /proc/<PID>/stack`: Shows the process stack
- `cat /proc/<PID>/status`: Shows the process status (check if a process is masquerading as a kernel process: if process name in brackets [NAME] → Kthread must be 1 - True, kernel thread)
- `ls -al /proc/<PID>`:
  - `cwd -> /$DIR`: shows the process working directory
  - `exe -> /$DIR/$FILE`: shows where the binary was stored
- `# awk '{print $22}' /proc/<PID>/stat`: prints the process start time
- `# stat /proc/<PID>`: General process information
- `#lsof -i -P`: list open connections → drill down on PID (`/proc/<PID>`) → drill donw with 'strings'
- `#strings /path/to/binary`: Outputs the strings from a binary (`listen()`, `bind()`, `accept()`, IP addresses, etc)
- `#cat /proc/<pid>/cmdline`: Show the command-line arguments of a running process
- check process name discrepancies between `/proc/<pid>/comm`, `/proc/<pid>/cmdline` additionnaly check symbolic link mismatch `#ls -l /proc/<pid>/exe`
## Persistence, overview
![Linux persistence overview - credits to Pepe Berba](../Images/linux-persistence-schema.png)
### Persistence techniques (non exhaustive list)
#### [System boot: Sytem V, Upstart, Systemd, Run Control](#system-boot-sytem-v-upstart-systemd-run-control)
Different scripts are run during system boot. These scripts can be created or modified to gain persistence.  
1. **System V (SysV)**  
Older init system.  
Startup, running and shutdown scripts in `/etc/init.d/` and executed as `root` on boot (compatibility through `systemd-generator`).  
Scripts are often linked to runlevel directories, determining when they are run: `/etc/rc0.d/`, `/etc/rc1.d/`,`/etc/rc2.d/`, etc.  
2. **Upstart**  
Older init system.  
System-wide scripts in `/etc/init/`.  
User-session mode scripts in `~/.config/upstart/`, `~/.init/`,`/etc/xdg/upstart/`,`/usr/share/upstart/sessions/`.
3. **Systemd**  
System ans service manager for Linux, replacement for SysVinit. Systemd operates with `unit files`, defing how services are started, stopped or managed.  
There are different types of `unit files`: `Service` (for managing long-running processes - typically deamons), `Timer` (similar to cron jobs).  
- **Systemd Services**  
System-wide services: `/run/systemd/system/`, `/etc/systemd/system/`, `/etc/systemd/user/`, `/usr/local/lib/systemd/system/`, `/lib/systemd/system/`, `/usr/lib/systemd/system/`, `/usr/lib/systemd/user/`  
User-specific services: `~/.config/systemd/user/`, `~/.local/share/systemd/user/`
- **Systemd Timers**  
Each `.timer`file must have a corresponding `.service` file with the same name.
System-wide timers: `/etc/systemd/system/`, `/usr/lib/systemd/system`,
User-specific timers: `~/.config/systemd/`  
- **Systemd Generator**  
Generators are executables run by systemd at bootup or during configuration reloads.  
System-wide generators: `/etc/systemd/system-generators/`. `/usr/local/lib/systemd/system-generators/`. `/lib/systemd/system-generators/`. `/etc/systemd/user-generators/`. `/usr/local/lib/systemd/user-generators/`. `/usr/lib/systemd/user-generators/`  
`systemd-rc-local-generator`, `rc-local.service`: Compatibility generator and service to start `/etc/rc.local` during boot.
4. **rc.common, rc.local**  
Deprecated and replaced by Systemd (compatibility through `systemd-generator`).  
The `rc.local`, `rc.common` files can start customer apps, services, scripts or commands at start-up.
Config file `/etc/rc.*local*`
5. **initrd and initramfs**
See [virtualization](#ram-and-virtualization)
#### User Accounts, Authentication
1. **User Accounts and Groups**  
[See](#users-user-groups-and-authentication-ssh)
2. **SSH Keys**  
[See](#users-user-groups-and-authentication-ssh)
3. **MOTD**  
Message of the day (MOTD) is a message presented to a user when he/she connects via SSH or a serial connection.
If activated, MOTD scripts are executed as `root` every time a user connects to a Linux system.
These scripts can be modified to gain persistence.
Config files in `/etc/update-motd.d/`
4. **XDG Autostart**  
XDG Autostart entries can be used to execute arbitrary commands or scripts when a user logs in.  
System-wide configs: `/etc/xdg/autostart/`, `/usr/share/autostart/`  
User-specific configs: `~/.config/autostart/`, `~/.local/share/autostart/`, `~/.config/autostart-scripts/`  
Root-specific configs: `/root/.config/autostart/`, `/root/.local/share/autostart/`, `/root/.config/autostart-scripts/`  
#### Jobs, Crons, Timers, Automated actions  
1. **At job** (one time jobs)  
Config files in `/var/spool/cron/atjobs/`  
Job detail in `/var/spool/cron/atspool/`  
2. **Cron Job** (recuring jobs)  
User-specifc cron job settings:  
`/var/spool/cron/`, `/var/spool/cron/crontabs/`  
System-wide cron job settings:  
`/etc/crontab`, `/etc/cron.d/`, `/etc/cron.daily/`, `/etc/cron.hourly/`, `/etc/cron.monthly/`, `/etc/cron.weekly/`  
3. **UDEV**  
Device manager for the Linux kernel. When a device is added to the system (USB drive, keyboard or network interface, etc) UDEV triggers predefined actions (rules).  
These rules can be created or manipulated to gain persistence.
UDEV rule files in:  
`/etc/udev/rules.d/`, `/run/udev/rules.d/`, `/usr/lib/udev/rules.d/`, `/usr/local/lib/udev/rules.d/`, `/lib/udev/`
5. Additionnal persistence mechanisms: `Anacron`, `Fcron`, `Task Spooler`, `Batch`.
#### [Shared objects/libraries](#shared-object-library)
1. LD_PRELOAD
`LD_PRELOAD` is an environment variable used to specify a shared library (or multiple libraries) that should be loaded before any other shared libraries () when executing a program. This allows to override functions in the standard library or other shared libraries without modifying the original binary.
- malicious process name (`/proc/<pid>/comm` and `/proc/<pid>/cmdline`) inherits that of a legitimate executable
- symbolic link `/proc/<pid>/exe` points to the legitimate binary
- no `ptrace`systeem call for process injection
- possible to remove `LD_PRELOAD` environment variable
- `#ps eaux | cat | grep LD_PRELOAD  | grep -v grep`
- `#lsof -p <pid>`
- `#ls /etc/ld.so.preload` (system-wide config)
#### Shell configurations
Different scripts are executed when a shell starts or ends.
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
Inspect Bash logout files: Linux.System.BashLogout
#### System Binaries
1. Living of the Land Binaries
See https://gtfobins.github.io/
 - Reverse shell: https://gtfobins.github.io/#+reverse%20shell
 - Non-interactive reverse shell: https://gtfobins.github.io/#+non-interactive%20reverse%20shell
 - Bind shell: https://gtfobins.github.io/#+bind%20shell
 - Non-interactive bind shell: https://gtfobins.github.io/#+non-interactive%20bind%20shell
2. Modified or substituted system binaries
 - for example, replace `/bin/false` with `/bin/bash` (usefull to hide a shell-login in `/etc/passwd`)
3. System Binary Wrapping
Replace a system binary by a malicious one, executing additionnal code without breaking the functionnality of the original system binary.
 - compare binary hashes to known-good ones (`#sha256sum <file>`)
 - monitor file integrity with AIDE, `#rpm -Va` (Red Hat)
4. Packet Manager 
 Modified packet manager configurations
  - `/etc/apt/apt.conf.d/*`
  - `/usr/lib/python*/site-packages/dnf-plugins/*`
  - `/etc/dnf/plugins/*`
  - `/usr/lib/yum-plugins/*`
  - `/etc/yum/pluginconf.d/*`
#### [Loadable Kernel Modules (LKM)](#loadable-kernel-modules-lkm)
 Loadable kernel modules can be dynamically loaded into the Linux Kernel at runtime to extend its functionality. There is no need to recompile the kernel or reboot the machine to apply the change. A malicious kernel module can hook kernel functions allowing to manipulate: Syscall table, Kprobes, Ftrace, VFS.
 **Hunting**
 - look for commands containing `#insmod`, `#rmmod`, `#modprobe`, `#lsmod`
 - `#cat /proc/modules`: Currently loaded kernel modules.
 - `# cat /proc/modules | grep OE`: Find unsigned or out-of-tree loaded modules.
 - `/sys/module/`: inforamtion about currently loaded kernel modules.
 - check kernel taint: `#cat /proc/sys/kernel/tainted`, `#dmesg | grep taint`
 see https://docs.kernel.org/admin-guide/tainted-kernels.html
 See external [tools](#rootkits-user-space-and-kernel-space) under the "Rootkit" part.
#### [RAM and Virtualization](#ram-and-virtualization)
1. initrd, initramfs
Initramfs is a temporary file system mounted during the early boot process, before the root file system is mounted. The `/boot` directory where initramfs is stored is not monitored against integrity and makes it a perfect place to hide malicious code. 
 - Check `/proc/<pid>/ns` links
 - Check Kernel threads proc entries (ppid != 0)
2. Malicious VM or Container (tbd)
3. RAM (tbd)
#### Rootkits, User- and Kernel-Space
Rootkits can be tricky to detect as they have different mechanisms to hide on an infected system. On the other hand, it is difficult to build stable kernel-rootkits in Linux and any sudden system instabilities (crash, reboot) could indicate their presence.  
Rootkits can modify or hide following elements making their manual detection challenging:
- file content (hiding rootkit config between tags in config files or hiding a user in `/etc/passwd` and `/etc/shadow`)  
Note: to uncloak a hidden file content → `#grep . <file>` (will stream the file content)
- files and directores
- processes
- network traffic
- kernel modules
Rootkits persistence mechanisms, see [system boot](#system-boot-sytem-v-upstart-systemd-run-control), [Shared objects/libraries](#shared-object-library), [Loadable Kernel Modules (LKM)](#loadable-kernel-modules-lkm), [Virtualization](#virtualization).  
There is no silver bullet to detect rootkits using common Linux system utilities. It is recommended to compare the subject machine to a known-good VM or to retrieve the same information in multiple different ways (for example compare the loaded kernel modules with `lsmod`, `cat /proc/modules`, `kmod list`).  
Following are some external tools that can help in their detection. If it is not possible to install these tools on the subject machine (remember to modify as little as possible on a subject machine when doing a forensic analysis), then the recommended method would be to take a memory image (with LiME) and analyse it with Volatility (a separated doc for this process will follow).  
Note that some of the listed tools don't required any installation on a subject machine and are therfore very usefull for a live analysis.  
**Rootkit Detection Tools**  
|Tool|Details|
|---|---|
| Sunlight | https://github.com/tstromberg/sunlight.git <br> set of powerfull bash scripts |
| LinuxCatScale | https://github.com/WithSecureLabs/LinuxCatScale <br> bash script that uses live-of-the-land tools |
| UAC | https://github.com/tclahr/uac <br> Use of native binaries and tools + **Runs everywhere with no dependencies (no installation required)** |
| rkhunter | Rootkit, backdoor and local exploits scanner. |
| chrootkit | Rootkit scanner. |
| unhide | https://salsa.debian.org/pkg-security-team/unhide <br> (part of Kali) find processes and TCP/UDP ports hidden by rootkits |
| ClamAV | Antivirus scanner for Linux. |
| bpftrace| https://github.com/bpftrace <br> Dynamic tracing tool using eBPF. A bunch of detection scripts are available. |
| Tracee | https://github.com/aquasecurity/tracee <br> Dynamic tracing tool using eBPF. A bunch of detection scripts are available. |
| Falco | https://github.com/falcosecurity/falco <br> Parses system calls against rules and alerts for violations. |
| Velociraptor | https://github.com/Velocidex/velociraptor <br> Powerful hunting tool. Available rootkit artifacts:<br> Exchange.Linux.Collection.CatScale<br> Exchange.Generic.Collection.UAC |
| Sandfly | (licensed tool)<br> Will literally tear appart anything malicious on a Linux machine. Check out where its name came from. <br>  **No installation required.** | 
#### !Velociraptor artifacts:

Default artifact: Linux.Sys.Services
Default artifact: Linux.Sys.Crontab
Or with custom artifact: Linux.Collection.Autoruns
## !Privilege Escalation, overview
## !Exfiltration
## !Useful Velociraptor Artifacts
- Linux.Detection.Yara.Process
- Linux.Search.FileFinder

To Do:
- test artifact in other distro:
   - Linux.Collection.CatScale
   - Exchange.Linux.Detection.IncorrectPermissions/Discrepancies
- create artifact for Shell Configuration files
- test ssh bruteforce and check logs


## ++++++++++++++++++++++++++++Clean END++++++++++++++++++++++++++++++++++++++++++++++++++
- environment variables and can be set to execute arbitrary commands whenever an action is about to take place like git log and its
- respective environment variable, GIT_PAGER
- [Web Shell](#web-shell) (webserver dir)


## Shared object Library
To Check:
- Env virable LD_PRELOAD in /etc/profile or a script in /etc/profile.d/
- File /etc/ld.so.preload
- Otherwise, inspect individual processes
- Use tools like chkrootkit and rkhunter to scan for rootkits and suspicious files.

## Startup file
Commonly targeted files include ~/.bashrc, ~/.profile, or ~/.bash_profile

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

## Privilege Escalation, overview
1. [Processes Privilege Escalation](#processes-privilege-escalation)
2. [Linux Kernel Vulnerability](#linux-kernel-vulnerability)

## Processes Privilege Escalation
**Detection with Velociraptor**  
Artifact: Exchange.Linux.PrivilegeEscalationDetection
### CVE-2021-4034
Polkit vulnerability, with `pkexec` commmand.  
**Detection with Velociraptor**  
Artifact: Exchange.Linux.Detection.CVE20214034



## Shell
keygen command (lateral movement)

# 04 Privilege Escalation

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

# 06 Credential Access

1. [Read /etc/shadow](#read-etcshadow)
2. [SSH Password Spraying](#ssh-password-spraying)
3. [SSHD Sniffing with Strace](#sshd-sniffing-with-strace)
4. [PAM auth() Sniffing with bpftrace](#pam-auth-sniffing-with-bpftrace)

## PAM auth() Sniffing with bpftrace

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

# (wip doc) Live Analysis Process
1. Mounting known-good binaries
2. Using netcat
3. Using Velociraptor
4. Dump RAM
5. Volatility (create profile + analyse dump)

