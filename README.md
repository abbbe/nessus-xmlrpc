This is a fork of https://code.google.com/p/nessusxmlrpc/.


#### nmap_scan.py

This script will perform a full TCP (0-65535) / UDP (top 1000) port scan with nmap, upload the XML output file to 
Nessus, create a custom policy based on this file and launch a new scan.

```shell
$ python nmap_scan.py
Usage: nmap_scan.py targets_file project_name config_file
$ python nmap_scan.py hacme_targets.txt HacmeCorp nessus.conf
```

Content of the target file has to follow the nmap format (See http://nmap.org/book/man-target-specification.html).
