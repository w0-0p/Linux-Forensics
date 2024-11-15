# Linux Live Analysis Knowledge Base, Tips & Tricks
1. [System Infos and Settings](#system-infos-and-settings)
2. [Users, User Groups and Authentication (SSH)](#users-user-groups-and-authentication-ssh)
3. [Files, Directories and Binaries](#files-directories-and-binaries)
4. [System Logs](#system-logs)
5. [Processes](#processes)
6. [Persistence, overview](#persistence-overview)
7. [General Velociraptor artifacts](#general-velociraptor-artifacts)

## System Infos and Settings
General System Overview
|Command|Output|
|---|---|
**System Information** 
| `ls` | Note: timestamps can easily be manipulated. Don't trust 'ls' timestamps. |
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

**Useful Velociraptor Artifacts**
- `Exchange.Linux.Collection.SysConfig`: collects system configurations
- `Linux.Mounts`: lists mounted filesystems by reading `/proc/mount`
- `Exchange.Linux.Collection.NetworkConfig`: collects network config files
- `Exchange.Linux.Network.Netstat`: parses `/proc` and reveal information about current network connections
- `Linux.Network.NetstatEnriched`: reports network connections, and enrich with process information
- `Exchange.Linux.Network.NM.Connections`: lists the NetworkManager state, configured connections and settings
- `Linux.Proc.Arp`: collects ARP table via `/proc/net/arp`
-`Linux.Sys.CPUTime`: displays information from `/proc/stat` about the time the cpu cores spent in different parts of the system

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
- `Linux.Users.InteractiveUsers`: gets the interactive users
- `Linux.Sys.LastUserLogin`: retrieve wtmp file content (successful logins and logouts)
- `Linux.Users.InteractiveUsers`: retrieve the interactive users (shell login)
- `Linux.Ssh.AuthorizedKeys`: retrieve authorized SSH keys
- `Linux.Ssh.PrivateKeys`: retrieve private keys + checks if encrypted or not
- `Linux.Ssh.KnownHosts`: parses ssh known hosts files
- `Exchange.Linux.Detection.SSHKeyFileCmd`: parse `~/.ssh/authorizedkey` and `~/.ssh/id*.pub` looking for the command option
- `Exchange.Linux.System.PAM`: enumerates applicable lines from the files that reside in `/etc/PAM.d/`

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
- `Exchange.Linux.Detection.IncorrectPermissions`: verify files/dirs and checks whether they have the expected owner, group owner and mode
- `Linux.Search.FileFinder`: Find files on the filesystem using the name or content
- `Exchange.Linux.Forensics.RecentlyUsed`: retrieves a list of recent files accessed by applications

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
- alternatives for Linux: ebpf, auditd, and others

**Useful Velociraptor Artifacts**
- `Exchange.Linux.Collection.SysLogs`: Collects system logs
## Processes  
Suspicious processes:
- process named to look legit
- open ports that seem odd
- outbound connections that seem odd
- deleted processes with open ports
- deleted binary

Commands:
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
  - `cwd -> /$DIR`: Shows the process working directory
  - `exe -> /$DIR/$FILE`: Shows where the binary was stored
- `# awk '{print $22}' /proc/<PID>/stat`: Prints the process start time
- `# stat /proc/<PID>`: General process information
- `#lsof -i -P`: Lists open connections → drill down on PID (`/proc/<PID>`) → drill donw with 'strings'
- `#strings /path/to/binary`: Outputs the strings from a binary (`listen()`, `bind()`, `accept()`, IP addresses, etc)
- `#cat /proc/<pid>/cmdline`: Show the command-line arguments of a running process
- Check process name discrepancies between `/proc/<pid>/comm`, `/proc/<pid>/cmdline` additionnaly check symbolic link mismatch `#ls -l /proc/<pid>/exe`

**Velociraptor Artifacts**
- `Linux.Sys.Pslist`: lists processes and their running binaries
- `Linux.Detection.Yara.Process`: runs YARA over processes in memory
- `Exchange.Linux.PrivilegeEscalationDetection`: identifies processes running as root that were spawned by non-priviledged processes
- `Linux.Events.ProcessExecutions`: collects process execution logs from the Linux kernel (requires `auditctl`)
- `Exchange.Linux.Detection.MemFD`: parses `/proc/*/exe` files and look for processes that have been executed from memory via `memfd_create()`
- `Linux.Triage.ProcessMemory`: dumps process memory


## Persistence, overview
![Linux persistence overview - credits to Pepe Berba](../Images/linux-persistence-schema.png)

### System boot: Sytem V, Upstart, Systemd, Run Control
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
**Systemd Services**  
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

**Velociraptor Artifacts**
- `Linux.Sys.Services`: parses services from systemctl

### User Accounts, Authentication
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

### Jobs, Crons, Timers, Automated actions  
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

**Velociraptor Artifacts**
- `Linux.Sys.Crontab`: parses information from crontab
- `Exchange.Linux.Collection.Autoruns`: collects various autorun files
- `Exchange.Linux.Sys.SystemdTimer`: parses content of Systemd timers

### Shared objects/libraries
**LD_PRELOAD**  
`LD_PRELOAD` is an environment variable used to specify a shared library (or multiple libraries) that should be loaded before any other shared libraries () when executing a program. This allows to override functions in the standard library or other shared libraries without modifying the original binary.
- malicious process name (`/proc/<pid>/comm` and `/proc/<pid>/cmdline`) inherits that of a legitimate executable
- symbolic link `/proc/<pid>/exe` points to the legitimate binary
- no `ptrace`systeem call for process injection
- possible to remove `LD_PRELOAD` environment variable
- `#ps eaux | cat | grep LD_PRELOAD  | grep -v grep`
- `#lsof -p <pid>`
- `#ls /etc/ld.so.preload` (system-wide config)

**Velociraptor Artifacts**
- `Linux.Sys.Maps`: parses the `/proc/*/maps` to link mapped files into the process

### Shell configurations, Environment Variables
1. **Shell scripts**  
Different scripts are executed when a shell starts or ends.

| Files | Working |
|-------|---------|
| `/etc/bash.bashrc` | systemwide files executed at the start of interactive shell |
| `/etc/bash_logout` | Systemwide files executed when we terminate the shell |
| `~/.bashrc`	| Widly exploited user specific startup script executed at the start of shell |
| `~/.bash_profile`, `~/.bash_login`, `~/.profile` | User specific files , but which found first are executed first |
| `~.bash_logout` | User specific files, executed when shell session closes |
| `~/.bash_logout` | User-specific clean up script at the end of the session |
| `/etc/profile` | Systemwide files executed at the start of login shells |
| `/etc/profile.d` | all the .sh files are executed at the start of login shells |

2. **Environment Variables**  
Each process has en environment list, wich is a set of environment variables. When a new process is created via *fork()*, it inherits a copy of its parent's environment. There are multiple use cases for environment variables. For example the env. variable `SHELL` defines the path to the shell that programms will use when they need a shell, or `HOME` that defines the home directory of a user.
There are local and system-wide environment variables.

**Velociraptor Artifacts**
- `Exchange.Linux.Collection.History`: Collects history files
- `Exchange.Linux.Collection.UserConfig`: Collects user configurations
- `Exchange.Linux.System.BashLogout`: capture Bash logout files

### System Binaries
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
    - monitor file integrity with AIDE, `#rpm -Va` (Red Hat), `#dpkg --verify`
4. Modified packet manager configurations
    - `/etc/apt/apt.conf.d/*`
    - `/usr/lib/python*/site-packages/dnf-plugins/*`
    - `/etc/dnf/plugins/*`
    - `/usr/lib/yum-plugins/*`
    - `/etc/yum/pluginconf.d/*`

**Velociraptor Artifacts**
- `Linux.Debian.AptSources`: parses Debian apt sources
- `Exchange.Linux.Sys.APTHistory`: parses the apt `history.log`, as well as archived history logs
- `Linux.Debian.Packages`: parse dpkg status file
- `Linux.RHEL.Packages`: parses packages installed from dnf

### Loadable Kernel Modules (LKM)
Loadable kernel modules can be dynamically loaded into the Linux Kernel at runtime to extend its functionality. There is no need to recompile the kernel or reboot the machine to apply the change. A malicious kernel module can hook kernel functions allowing to manipulate: Syscall table, Kprobes, Ftrace, VFS.

**Hunting**
- look for commands containing `#insmod`, `#rmmod`, `#modprobe`, `#lsmod`
- `#cat /proc/modules`: Currently loaded kernel modules.
- `#cat /proc/modules | grep OE`: Find unsigned or out-of-tree loaded modules.
- `/sys/module/`: inforamtion about currently loaded kernel modules.
- check kernel taint: `#cat /proc/sys/kernel/tainted`, `#dmesg | grep taint`  
see https://docs.kernel.org/admin-guide/tainted-kernels.html  

See external [tools](#rootkits-user--and-kernel-space) and Velociraptor artifacts under the "Rootkit" part.

### RAM and Virtualization
1. **initrd, initramfs**  
Initramfs is a temporary file system mounted during the early boot process, before the root file system is mounted. The `/boot` directory where initramfs is stored is not monitored against integrity and makes it a perfect place to hide malicious code. 
    - Check `/proc/<pid>/ns` links
    - Check Kernel threads proc entries (ppid != 0)
2. **Malicious VM or Container** (tbd)
3. **RAM** (tbd)

### Rootkits, User- and Kernel-Space
Rootkits can be tricky to detect as they have different mechanisms to hide on an infected system. On the other hand, it is difficult to build stable kernel-rootkits in Linux and any sudden system instabilities (crash, reboot) could indicate their presence.  

Rootkits can modify or hide following elements making their manual detection challenging:
- file content (hiding rootkit config between tags in config files or hiding a user in `/etc/passwd` and `/etc/shadow`)  
Note: to uncloak a hidden file content → `#grep . <file>` (will stream the file content)
- files and directores
- processes
- network traffic
- kernel modules

For rootkits persistence mechanisms, see [system boot](#system-boot-sytem-v-upstart-systemd-run-control), [Shared objects/libraries](#shared-objectslibraries), [Loadable Kernel Modules (LKM)](#loadable-kernel-modules-lkm), [Virtualization](#ram-and-virtualization).  

There is no silver bullet to detect rootkits using common Linux system utilities. It is recommended to compare the subject machine to a known-good VM or to retrieve the same information in multiple different ways (for example compare the loaded kernel modules with `lsmod`, `cat /proc/modules`, `kmod list`).  
Following are some external tools that can help in their detection. If it is not possible to install these tools on the subject machine (remember to modify as little as possible on a subject machine when doing a forensic analysis), then the recommended method would be to take a memory image (with LiME) and analyse it with Volatility (a separated doc for this process will follow).  
Note that some of the listed tools don't required any installation on a subject machine and are therfore very usefull for a live analysis.  

**Velociraptor Artifacts**
- `Linux.Proc.Modules`:lists loaded modules via `/proc/modules`
- `Exchange.Linux.Detection.BPF`: parses `/proc/*/exe` files and looks for processes that have been executed from memory via memfd_create()
- `Exchange.Linux.Detection.BPFmaps`: parses `/proc/fd/` files and looks for processes that have been created by bpf-maps

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

## General Velociraptor Artifacts

| Name | Details |
|---|---|
| Linux.Network.PacketCapture | leverages tcpdump to natively capture packets |
| Exchange.Linux.Collection.CatScale | Uses CatScale to collect multiple artifacts |
| Exchange.Generic.Collection.UAC | Uses UAC to collect multiple artifacts |
| Exchange.Linux.CentOS.Memory.Acquisition | Acquires a full memory image (LiME) |
| Exchange.Linux.Centos.Volatility.Create.Profile | Creates Volatility profile |
| Exchange.Linux.Collection.BrowserHistory | Collects Browser History |
| Linux.Applications.Chrome.Extensions | Fetch Chrome extensions |