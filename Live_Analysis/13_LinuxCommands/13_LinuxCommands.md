
Grep
Show content hidden by a rootkit in files (for example between tags like <reptile> </reptile>), by outputting the file content as a stream:
grep . /etc/crontab

Cat
List of kernel functions that are currently enabled for tracing:
cat /sys/kernel/debug/tracing/enabled_functions
Source of great evidence about recent eBPF operations:
cat /sys/kernel/debug/tracing/trace
# Commands



# Regex
## Parameters
- r = recursive, through all the files in the directory
- P = Perl-compatible Regex (advanced search)
## IPv4 (with or without port)
^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(?::\d{1,5})?$
## examples
- grep -P \<REGEX> /path/to/file
- grep -rP \<REGEX> /path/to/dir/


