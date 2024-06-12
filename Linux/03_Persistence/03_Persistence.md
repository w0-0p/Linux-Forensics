# Introduction
Excellent resource: https://hadess.io/the-art-of-linux-persistence/

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



[def]: #systemd-timers