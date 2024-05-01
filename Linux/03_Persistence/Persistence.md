# Introduction
Excellent resource: https://hadess.io/the-art-of-linux-persistence/

1. [Account Creation (User or Root)](#account-creation-user-or-root)
2. [SSH Authorized Keys](#ssh-authorized-keys) 
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

### Check it with Velociraptor
Default artifact: Linux.Sys.Users

### Custom Notebook query
```sql
/*
# Linux.Sys.Users
*/
SELECT * FROM source(artifact="Linux.Sys.Users")
WHERE NOT Shell =~ "nologin"
and NOT Shell =~"false"
LIMIT 50
```

## SSH

### Authorized Keys

Check authorized_keys file.

/home/\<username>/.ssh/authorized_keys

### Check it with Velociraptor:
Default artifact: Linux.Ssh.AuthorizedKeys

### Private Keys

Check private k

## Cron Jobs

Check cron tab files in:

– /etc/crontab
– /etc/cron.d/*
– /etc/cron.{hourly,daily,weekly,monthly}/*
– /var/spool/cron/crontab/*

Check it with Velociraptor:


## Systemd Services and Timers

Check service files: 
/etc/systemd/system/*.service

Check timer files:
/etc/systemd/system/*.timer

Check it with Velociraptor:

## Shell Configuration Modification

Files	Working
/etc/bash.bashrc    systemwide files executed at the start of interactive shell
(tmux)
/etc/bash_logout	Systemwide files executed when we terminate the shell
~/.bashrc	        Widly exploited user specific startup script executed at
                    the start of shell
~/.bash_profile, ~/.bash_login, ~/.profile	User specific files , but which found first are executed
                                            first
~.bash_logout	    User specific files, executed when shell session closes
~/.bash_logout	    User-specific clean up script at the end of the session
/etc/profile	    Systemwide files executed at the start of login shells
/etc/profile.d	    all the .sh files are exeucted at the start of login shells

Check it with Velociraptor:

## Shared object Library

## SUID

## rc.common

## Systemd Services

## Trap

## Startup file

## System Call

## MOTD Backdooring

## APT Backdooring

## Git Backdooring

## Config

## Backdooring OpenVPN



[def]: #systemd-timers