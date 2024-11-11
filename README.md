# Aims
The aims of this doc are:
1. Gather known techniques for compromising Linux systems.
2. Provide Threat-Hunting guides and procedures, when possible with Velociraptor.
3. Improve Velociraptor's Linux detection with additionnal or improved artifacts.

# Credits and Resources
This doc is based on following sources:
1. https://edu.defensive-security.com/linux-attack-live-forensics-at-scale
2. https://hadess.io/the-art-of-linux-persistence/
3. https://pberba.github.io/security/2021/11/22/linux-threat-hunting-for-persistence-sysmon-auditd-webshell/#overview-of-blog-series
4. https://gtfobins.github.io
5. https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/linux-forensics
6. https://www.youtube.com/@SandflySecurity
7. https://www.youtube.com/playlist?list=PLC3HQmfNLLKSzgW4z-QsIFz0j2BVMQbm_
8. https://righteousit.com
9. https://attack.mitre.org/matrices/enterprise/linux/
10. https://www.youtube.com/results?search_query=hal+pomeranz+


# Recommended Books  
- Practical Linux Forensics, Bruce Nikkel  
- Linux Forensics, Philip Polstra  

To Do:
- test artifact in other distro:
   - Linux.Collection.CatScale
   - Exchange.Linux.Detection.IncorrectPermissions/Discrepancies
- create artifact for Shell Configuration files
- test ssh bruteforce and check logs