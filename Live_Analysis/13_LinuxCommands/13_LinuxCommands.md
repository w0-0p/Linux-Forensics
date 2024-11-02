# Commands
BPF
bpftool prog show
bpftool prog trace show
dmesg | grep -E '(trace|hook|probe|bpf)'

# Regex
## Parameters
- r = recursive, through all the files in the directory
- P = Perl-compatible Regex (advanced search)
## IPv4 (with or without port)
^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(?::\d{1,5})?$
## examples
- grep -P \<REGEX> /path/to/file
- grep -rP \<REGEX> /path/to/dir/


