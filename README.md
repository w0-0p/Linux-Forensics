# Aims
The aims of this doc are:
1. Gathering relevant TTPs threat actors can use in Linux (and some mainstream technologies) and organize them according the MITRE ATT&CK matrix.
2. Documenting how Velociraptor can be used to hunt for these TTPs.
3. Improve Velociraptor Linux detection with additionnal artifacts.

# Credits and Resources
This doc is based on following sources:
1. https://edu.defensive-security.com/linux-attack-live-forensics-at-scale
2. https://hadess.io/the-art-of-linux-persistence/
3. https://www.youtube.com/results?search_query=hal+pomeranz+
4. https://www.youtube.com/@SandflySecurity
5. https://www.youtube.com/playlist?list=PLC3HQmfNLLKSzgW4z-QsIFz0j2BVMQbm_
6. https://righteousit.com
7. https://gtfobins.github.io
8. https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/linux-forensics
9. https://attack.mitre.org/matrices/enterprise/linux/


# Recommended Books  
- Practical Linux Forensics, Bruce Nikkel  
- Linux Forensics, Philip Polstra  

To Do:
- test artifact in other distro:
   - Linux.Collection.CatScale
   - Exchange.Linux.Detection.IncorrectPermissions/Discrepancies
- create artifact for Shell Configuration files
- test ssh bruteforce and check logs