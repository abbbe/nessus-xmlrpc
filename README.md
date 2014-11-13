This is a fork of https://code.google.com/p/nessusxmlrpc/.


## Goals

Nessus is a commercial vulnerability scanner offered by Tenable Security. The current version provides a web interface using a client built on Adobe Flash and Flex. While this new interface is easy to use, there's no support for scheduling or automating scans; the process of starting scans and generating reports is largely manual. We want to achieve the following:

    * Perform automated scans. Organize target networks and use optimized scan configurations per target.
    * Provide for quick and visible reporting of scan results. 

The command-line tools that would otherwise be used for automating scans and generating reports are now deprecated according to the documentation and the company (Tenable) does not plan on supporting them going forward.

## Summary

NessusXMLRPC is a Python module I've written for automating tasks within the latest version of Nessus. While the XMLRPC interface exposed by Nessus provides complete control over application state and configuration, I've implemented only what we need for automating scanning and email reporting.
Usage

There are two components to the package; a new command-line utility and the XMLRPC module itself. If you wish to perform advanced automation of Nessus on your own, use NessusXMLRPC. Otherwise, the new command-line tool should suffice.
nessus.conf

The first step you should take is open the nessus.conf file and modify your settings:

```
# Defaults

[core]
server = nessus01
port = 8834
user = nessus
password = *pass*
logfile = /home/user/tools/nessus-xmlrpc/nessus.log
loglevel = debug
limit = 3
sleepmax = 600
sleepmin = 300

[smtp]
to = me@mydomain.com
from = security@mydomain.com
server = mysmtpserver
port = 25

[report]
outputdir = /home/user/tools/nessus-xmlrpc/reports
xsltproc = /usr/bin/xsltproc
xsltlog = /home/user/tools/nessus-xmlrpc/reports/xsltproc.log
xsl = /home/user/tools/nessus-xmlrpc/reports/html.xsl
```

A description of each of the settings is as follows:

* core.server 	Hostname or IP address of the Nessus server.
* core.port 	Port the Nessus server is listening on.
* core.user 	User account for connecting to the Nessus server.
* core.password 	Password for connecting to the Nessus server.
* core.logfile 	Output log file to use.
* core.loglevel 	Level of detail in the log. Possible values include debug, info, warning, error, and critical.
* core.limit 	Limit on the number of concurrently running scans.
* core.sleepmax 	Upper limit on random sleep time when polling for scan completion.
* core.sleepmin 	Lower limit on random sleep time when polling for scan completion.
* smtp.to 	Email address to send reports to.
* smtp.from 	Email address to send reports from.
* smtp.server 	SMTP server to use when sending reports.
* smtp.port 	Port on the SMTP server to use when sending reports.
* report.outputdir 	Output directory of all intermediate report files.
* report.xsltproc 	Location of xsltproc on the system.
* report.xsltlog 	Location of the xsltproc output log (transforming report).
* report.xsl 	Location of the XSL file used to transform reports. The default html.xsl can be downloaded directly from the Nessus server without authentication.

After modifying your settings, you're ready to use the CLI.

### nessus.py

The CLI replacement offers the following options:

```shell
kurtis@ubuntu:~/assess/tools/nessus-xmlrpc$ ./nessus.py
Usage: nessus.py [options]

Options:
  -h, --help     show this help message and exit
  -t TARGET      target string for Nessus scan
  -n NAME        name for the scan
  -p POLICY      policy (on server-side) to use in the scan
  -f INFILE      input file with multiple scans to run
  -c CONFIGFILE  configuration file to use
kurtis@ubuntu:~/assess/tools/nessus-xmlrpc$
```

Below are additional details on how each option may be used:
* -h 	Provides proper usage information.
* -t 	Used when performing only a single scan. Sets the target string for the single Nessus scan that's to be started.
* -n 	Used when performing only a single scan. Sets the name for the single Nessus scan that's to be started.
* -p 	Used when performing only a single scan. Sets the policy to be used for the single Nessus scan that's to be started.
* -f 	Used when performing multiple scans. The input file must have one scan per line with the fields scan name, target string, and policy name in that order separated by commas.
* -c 	Configuration file to use when automating tasks. Default is nessus.conf in the current working directory.

#### Performing a Single Scan

After modifying the variables in nessus.conf, you don't have to type as much on the command-line to launch a scan. Below is an example scan started against a test host, scan-host-01, using a policy configured through the web interface:

```
kurtis@ubuntu:~/assess/tools/nessus-xmlrpc$ ./nessus.py -n "scan-host-01" -t 192.168.1.121 -l "Workstations (Unauth)"
```
The output seen in the logfile nessus.log includes the following:
```
2010-12-16 13:51:08.264711    DEBUG CONF configfile = nessus.conf
2010-12-16 13:51:08.265078    DEBUG Logger initiated; Logfile: /root/tools/nessus-xmlrpc/trunk/nessus.log, Loglevel: 10
2010-12-16 13:51:08.265247    DEBUG CONF core.server = nessus-test01
2010-12-16 13:51:08.265398    DEBUG CONF core.port = 8834
2010-12-16 13:51:08.265589    DEBUG CONF core.user = nessus
2010-12-16 13:51:08.265731    DEBUG CONF core.password set
2010-12-16 13:51:08.265930    DEBUG CONF core.limit = 2
2010-12-16 13:51:08.266074    DEBUG CONF core.sleepmax = 10
2010-12-16 13:51:08.266213    DEBUG CONF core.sleepmin = 5
2010-12-16 13:51:08.266344    DEBUG CONF smtp.emailto = nessus@mydomain.com
2010-12-16 13:51:08.266463    DEBUG CONF smtp.emailfrom = nessus@mydomain.com
2010-12-16 13:51:08.266654    DEBUG CONF smtp.smtpserver = smtpserver
2010-12-16 13:51:08.266959    DEBUG CONF smtp.smtpport = 25
2010-12-16 13:51:08.267102    DEBUG CONF report.reports = /root/tools/nessus-xmlrpc/trunk/reports
2010-12-16 13:51:08.267240    DEBUG CONF report.xsltproc = /usr/bin/xsltproc
2010-12-16 13:51:08.267376    DEBUG CONF report.xsltlog = /root/tools/nessus-xmlrpc/trunk/reports/xsltproc.log
2010-12-16 13:51:08.267508    DEBUG CONF report.xsl = /root/tools/nessus-xmlrpc/trunk/reports/html.xsl
2010-12-16 13:51:08.267712    DEBUG PARSED scans: [{'policy': 'Workstations (Unauth)', 'name': 'Test Scan 01', 'target': '192.168.1.121'}]
2010-12-16 13:51:08.268075     INFO Nessus scanner started.
2010-12-16 13:51:08.298106     INFO Connected to Nessus server; authenticated to server 'nessus-test01' as user 'nessus'
2010-12-16 13:51:08.298429     INFO Starting with a single scan
2010-12-16 13:51:08.911890     INFO Scan successfully started; Owner: 'nessus', Name: 'Test Scan 01'
2010-12-16 13:51:08.912233     INFO Sleeping for 5 seconds, polling for scan completion
2010-12-16 13:51:14.063994     INFO Sleeping for 7 seconds, polling for scan completion
2010-12-16 13:51:21.328478     INFO XML report saved as '/root/tools/nessus-xmlrpc/trunk/reports/TestScan01.xml'
2010-12-16 13:51:21.329298     INFO HTML report saved as '/root/tools/nessus-xmlrpc/trunk/reports/TestScan01.html'
2010-12-16 13:51:22.691210     INFO Email report sent to 'nessus@mydomain.com' from 'nessus@mydomain.com' including '/root/tools/nessus-xmlrpc/trunk/reports/TestScan01.zip'
2010-12-16 13:51:22.691685     INFO All done; closing
```

You can see above that the scan runs, the nessus.py polls the Nessus server for scan status periodically, and the report is sent as soon as the scan is complete.

For the sake of this example, I administratively stopped the scan, the server detected the scan as complete and generated the report.

#### Performing Multiple Scans

This is where NessusXMLRPC gets most of its power. Again, make sure you've tweaked your configuration file (nessus.conf), it will help save typing and time. First, here are the contents of a text file configured with all of my scans:

```
kurtis@ubuntu:~/assess/tools/nessus-xmlrpc$ cat us.txt
ACME Austin HQ,192.168.1.0/24,Workstations (Unauth)
ACME Barbados,192.168.2.0/24,Workstations (Unauth)
ACME Sydney,192.168.3.0/24,Workstations (Unauth)
ACME London,192.168.4.0/24,Workstations (Unauth)
```

The scans are specified one per line in the following format:

```
<scan name>,<target(s)>,<policy>
```

All fields must be separated by a comma (,). The scan name is intended to properly identify the scan, the target string must be a Nessus compatible target string (CIDR notation is common), and the policy must correspond with the name of a configured policy in the Nessus web interface. When you launch nessus.py and specify a file for input, it launches all of the scans at once (concurrently):

```
kurtis@ubuntu:~/assess/tools/nessus-xmlrpc$ ./nessus.py -f us.txt
```

All of the scans are launched and indicated in the log file. The scans are monitored until they're all complete. Once complete, reports are generated and sent for each scan.

```
2010-12-16 14:02:29.833129    DEBUG CONF configfile = nessus.conf
2010-12-16 14:02:29.833394    DEBUG Logger initiated; Logfile: /root/tools/nessus-xmlrpc/trunk/nessus.log, Loglevel: 10
2010-12-16 14:02:29.833526    DEBUG CONF core.server = nessus-test01
2010-12-16 14:02:29.833666    DEBUG CONF core.port = 8834
2010-12-16 14:02:29.833790    DEBUG CONF core.user = nessus
2010-12-16 14:02:29.833911    DEBUG CONF core.password set
2010-12-16 14:02:29.834068    DEBUG CONF core.limit = 2
2010-12-16 14:02:29.834195    DEBUG CONF core.sleepmax = 10
2010-12-16 14:02:29.834322    DEBUG CONF core.sleepmin = 5
2010-12-16 14:02:29.834457    DEBUG CONF smtp.emailto = nessus@mydomain.com
2010-12-16 14:02:29.834567    DEBUG CONF smtp.emailfrom = nessus@mydomain.com
2010-12-16 14:02:29.834676    DEBUG CONF smtp.smtpserver = smtpserver
2010-12-16 14:02:29.834792    DEBUG CONF smtp.smtpport = 25
2010-12-16 14:02:29.834904    DEBUG CONF report.reports = /root/tools/nessus-xmlrpc/trunk/reports
2010-12-16 14:02:29.835035    DEBUG CONF report.xsltproc = /usr/bin/xsltproc
2010-12-16 14:02:29.835155    DEBUG CONF report.xsltlog = /root/tools/nessus-xmlrpc/trunk/reports/xsltproc.log
2010-12-16 14:02:29.835287    DEBUG CONF report.xsl = /root/tools/nessus-xmlrpc/trunk/reports/html.xsl
2010-12-16 14:02:29.835405    DEBUG PARSED scans: [{'policy': 'Workstations (Unauth)', 'name': 'ACME Austin HQ', 'target': '192.168.1.0/24'}, {'policy': 'Workstations (Unauth)', 'name': 'ACME Barbados', 'target': '192.168.2.0/24'}, {'policy': 'Workstations (Unauth)', 'name': 'ACME Sydney', 'target': '192.168.3.0/24'}, {'policy': 'Workstations (Unauth)', 'name': 'ACME London', 'target': '192.168.4.0/24'}, {'policy': 'Workstations (Unauth)', 'name': 'ACME San Diego', 'target': '192.168.5.0/24'}, {'policy': 'Workstations (Unauth)', 'name': 'ACME New York', 'target': '192.168.6.0/24'}, {'policy': 'Workstations (Unauth)', 'name': 'ACME San Antonio', 'target': '192.168.7.0/24'}, {'policy': 'Workstations (Unauth)', 'name': 'ACME Boston', 'target': '192.168.8.0/24'}]
2010-12-16 14:02:29.835489     INFO Nessus scanner started.
2010-12-16 14:02:29.861836     INFO Connected to Nessus server; authenticated to server 'nessus-test01' as user 'nessus'
2010-12-16 14:02:29.862005     INFO Starting with multiple scans
2010-12-16 14:02:30.428167     INFO Scan successfully started; Owner: 'nessus', Name: 'ACME Austin HQ'
2010-12-16 14:02:31.036475     INFO Scan successfully started; Owner: 'nessus', Name: 'ACME Sydney'
2010-12-16 14:02:31.036817  WARNING Concurrent scan limit reached (currently set at 2)
2010-12-16 14:02:31.036906  WARNING Will monitor scans and continue as possible
2010-12-16 14:02:31.036998     INFO Sleeping for 10 seconds, polling for scan completion
2010-12-16 14:02:41.189488     INFO We can run more scans, resuming
2010-12-16 14:02:41.741407     INFO Scan successfully started; Owner: 'nessus', Name: 'ACME Barbados'
2010-12-16 14:02:41.741726  WARNING Concurrent scan limit reached (currently set at 2)
2010-12-16 14:02:41.741797  WARNING Will monitor scans and continue as possible
2010-12-16 14:02:41.742225     INFO Sleeping for 6 seconds, polling for scan completion
2010-12-16 14:02:47.895155     INFO We can run more scans, resuming
2010-12-16 14:02:48.491256     INFO Scan successfully started; Owner: 'nessus', Name: 'ACME London'
2010-12-16 14:02:48.491620  WARNING Concurrent scan limit reached (currently set at 2)
2010-12-16 14:02:48.491693  WARNING Will monitor scans and continue as possible
2010-12-16 14:02:48.491934     INFO Sleeping for 6 seconds, polling for scan completion
2010-12-16 14:02:54.643163     INFO Sleeping for 8 seconds, polling for scan completion
2010-12-16 14:03:02.802508     INFO We can run more scans, resuming
2010-12-16 14:03:03.399270     INFO Scan successfully started; Owner: 'nessus', Name: 'ACME San Diego'
2010-12-16 14:03:03.399598  WARNING Concurrent scan limit reached (currently set at 2)
2010-12-16 14:03:03.399670  WARNING Will monitor scans and continue as possible
2010-12-16 14:03:03.399979     INFO Sleeping for 5 seconds, polling for scan completion
2010-12-16 14:03:08.559223     INFO We can run more scans, resuming
2010-12-16 14:03:09.149278     INFO Scan successfully started; Owner: 'nessus', Name: 'ACME New York'
2010-12-16 14:03:09.149633  WARNING Concurrent scan limit reached (currently set at 2)
2010-12-16 14:03:09.149705  WARNING Will monitor scans and continue as possible
2010-12-16 14:03:09.149945     INFO Sleeping for 7 seconds, polling for scan completion
2010-12-16 14:03:16.333008     INFO We can run more scans, resuming
2010-12-16 14:03:16.993362     INFO Scan successfully started; Owner: 'nessus', Name: 'ACME San Antonio'
2010-12-16 14:03:16.993663  WARNING Concurrent scan limit reached (currently set at 2)
2010-12-16 14:03:16.993736  WARNING Will monitor scans and continue as possible
2010-12-16 14:03:16.994018     INFO Sleeping for 8 seconds, polling for scan completion
2010-12-16 14:03:25.151146     INFO We can run more scans, resuming
2010-12-16 14:03:25.775520     INFO Scan successfully started; Owner: 'nessus', Name: 'ACME Boston'
2010-12-16 14:03:25.775871  WARNING Concurrent scan limit reached (currently set at 2)
2010-12-16 14:03:25.775945  WARNING Will monitor scans and continue as possible
2010-12-16 14:03:25.776207     INFO Sleeping for 9 seconds, polling for scan completion
2010-12-16 14:03:34.930267     INFO Sleeping for 5 seconds, polling for scan completion
2010-12-16 14:03:40.152228     INFO XML report saved as '/root/tools/nessus-xmlrpc/trunk/reports/ACMEAustinHQ.xml'
2010-12-16 14:03:40.152978     INFO HTML report saved as '/root/tools/nessus-xmlrpc/trunk/reports/ACMEAustinHQ.html'
2010-12-16 14:03:40.233955     INFO Email report sent to 'nessus@mydomain.com' from 'nessus@mydomain.com' including '/root/tools/nessus-xmlrpc/trunk/reports/ACMEAustinHQ.zip'
2010-12-16 14:03:40.296977     INFO XML report saved as '/root/tools/nessus-xmlrpc/trunk/reports/ACMESydney.xml'
2010-12-16 14:03:40.297685     INFO HTML report saved as '/root/tools/nessus-xmlrpc/trunk/reports/ACMESydney.html'
2010-12-16 14:03:40.374522     INFO Email report sent to 'nessus@mydomain.com' from 'nessus@mydomain.com' including '/root/tools/nessus-xmlrpc/trunk/reports/ACMESydney.zip'
2010-12-16 14:03:40.436181     INFO XML report saved as '/root/tools/nessus-xmlrpc/trunk/reports/ACMEBarbados.xml'
2010-12-16 14:03:40.436950     INFO HTML report saved as '/root/tools/nessus-xmlrpc/trunk/reports/ACMEBarbados.html'
2010-12-16 14:03:40.499074     INFO Email report sent to 'nessus@mydomain.com' from 'nessus@mydomain.com' including '/root/tools/nessus-xmlrpc/trunk/reports/ACMEBarbados.zip'
2010-12-16 14:03:40.558770     INFO XML report saved as '/root/tools/nessus-xmlrpc/trunk/reports/ACMELondon.xml'
2010-12-16 14:03:40.559502     INFO HTML report saved as '/root/tools/nessus-xmlrpc/trunk/reports/ACMELondon.html'
2010-12-16 14:03:40.624087     INFO Email report sent to 'nessus@mydomain.com' from 'nessus@mydomainy.com' including '/root/tools/nessus-xmlrpc/trunk/reports/ACMELondon.zip'
2010-12-16 14:03:40.681251     INFO XML report saved as '/root/tools/nessus-xmlrpc/trunk/reports/ACMESanDiego.xml'
2010-12-16 14:03:40.682033     INFO HTML report saved as '/root/tools/nessus-xmlrpc/trunk/reports/ACMESanDiego.html'
2010-12-16 14:03:40.749228     INFO Email report sent to 'nessus@mydomain.com' from 'nessus@mydomain.com' including '/root/tools/nessus-xmlrpc/trunk/reports/ACMESanDiego.zip'
2010-12-16 14:03:40.813423     INFO XML report saved as '/root/tools/nessus-xmlrpc/trunk/reports/ACMENewYork.xml'
2010-12-16 14:03:40.814256     INFO HTML report saved as '/root/tools/nessus-xmlrpc/trunk/reports/ACMENewYork.html'
2010-12-16 14:03:40.890059     INFO Email report sent to 'nessus@mydomain.com' from 'nessus@mydomain.com' including '/root/tools/nessus-xmlrpc/trunk/reports/ACMENewYork.zip'
2010-12-16 14:03:40.970594     INFO XML report saved as '/root/tools/nessus-xmlrpc/trunk/reports/ACMESanAntonio.xml'
2010-12-16 14:03:40.971353     INFO HTML report saved as '/root/tools/nessus-xmlrpc/trunk/reports/ACMESanAntonio.html'
2010-12-16 14:03:41.046285     INFO Email report sent to 'nessus@mydomain.com' from 'nessus@mydomain.com' including '/root/tools/nessus-xmlrpc/trunk/reports/ACMESanAntonio.zip'
2010-12-16 14:03:41.110067     INFO XML report saved as '/root/tools/nessus-xmlrpc/trunk/reports/ACMEBoston.xml'
2010-12-16 14:03:41.110898     INFO HTML report saved as '/root/tools/nessus-xmlrpc/trunk/reports/ACMEBoston.html'
2010-12-16 14:03:41.186975     INFO Email report sent to 'nessus@mydomain.com' from 'nessus@mydomain.com' including '/root/tools/nessus-xmlrpc/trunk/reports/ACMEBoston.zip'
2010-12-16 14:03:41.187317     INFO All done; closing
```

### NessusXMLRPC

You should only need to use NessusXMLRPC directly if you must do something very specific. For instance, launching scans in response to an event. The sole class (Scanner) and all methods are documented using epydoc markup. Use epydoc to generate the documentation for all code. Below is a basic example on launching a scan using NessusXMLRPC:

```
#!/usr/bin/python

from NessusXMLRPC import Scanner

# Init the scanner - hostname, port, login, password
x = Scanner( "nessus-server1", 8834, login="nessus", password="*MASKED*")

# Start a scan - scan name, target, policy
scan = x.quickScan( "My Scan Name", "192.168.1.10", "Workstations (Unauth)")

print "Scan started. Name: %s, Owner: %s, UUID: %s" % (scan['scan_name'],scan['owner'],scan['uuid'])

x.logout()
```

```
kurtis@ubuntu:~/assess/tools/nessus-xmlrpc$ ./test.py
Scan started. Name: My Scan Name, Owner: nessus, UUID: ed094ee1-1033-cfc3-a9ed-41cda78b19708532dce28957eca3
```


## Conclusion

While NessusXMLRPC isn't a complete XMLRPC client implementation according to what's available, it achieves the immediate goals of automation and reporting. This tool allows for automation of the Nessus scanner while continuing to leverage the configurations managed through the web interface. In recognizing the problems addressed by this tool, I wish to release it as open-source to the community to further enable security teams tasked with such scanning. 

