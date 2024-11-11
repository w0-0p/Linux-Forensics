Notes from the Linux Forensics Course from Philip Polstra:  
https://www.youtube.com/playlist?list=PLC3HQmfNLLKSzgW4z-QsIFz0j2BVMQbm_

## Misc.  
- Taking notes: use a notebook with page numbers.

# Introduction
Excellent resource: https://hadess.io/the-art-of-linux-persistence/

### Rootkits
Linux tools:  
- sudo apt-get install chkrootkit  
sudo chkrootkit  
- sudo apt-get install rkhunter  
sudo rkhunter --check  


## Sysmon for Linux
- not maintained, not suitable for production
- alternatives for Linux: ebpf, auditd

## Detection scripts for Linux  
### Sunlight  
https://github.com/tstromberg/sunlight.git  
--> to be matched with Velociraptor hunts  
### OSQuery-Defense-Quit  
wget https://pkg.osquery.io/linux/osquery-5.10.2_1.linux_x86_64.tar.gz  
https://github.com/chainguard-dev/osquery-defense-kit  