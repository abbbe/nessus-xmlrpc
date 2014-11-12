#!/usr/bin/python
import sys, os
import subprocess
import json

import ConfigParser
from NessusXMLRPC import Scanner


if len(sys.argv) > 3:
    
    targetfile = sys.argv[1]
    projectname = sys.argv[2]
    configfile = sys.argv[3]

    config = ConfigParser.ConfigParser()
    config.readfp(open(configfile))
    server      = config.get('core', 'server')
    port        = config.getint('core', 'port')
    user        = config.get('core', 'user')
    password    = config.get('core', 'password')
    
    with open(targetfile) as f:
        targets = f.read().replace("\n", ",")[:-1]
    
    #Launch Nmap FullTCP and UDP scan on targets
    print "[+] Launching nmap scan against %s"%(targets)
    subprocess.call(["nmap", "-n", "-rH", "-sSU", "-Pn", "-pT:0-65535", "-oA", "%s_fulltcp_udp1000"%(projectname), targets, "-vvv"]) 
    filename = "%s_fulltcp_udp1000.xml"%(projectname)
 
    # Init the scanner - hostname, port, login, password
    x = Scanner(server, port, login=user, password=password)
 
    #Upload nmap scan XML output to Nessus 
    print "[+] Uploading file %s ..." % (filename)
    response = x.uploadFile(filename)
    if response["status"] == "OK":
        print "[+] File successfully uploaded."
        print "[+] Creating new policy ..."

	policy_name = "%s - Nmap Import Policy"%(projectname)
	policy_settings = {
	    "general.Basic.2" : "yes", 
	    "general.Port+Scanning.0" : 0, 
	    "general.Port+Scanning.5" : "no", 
	    "general.Port+Scanning.6" : "no",
	    "general.Port+Scanning.7" : "no",
	    "general.Port+Scanning.9" : "no",
	    "general.Port+Scanning.3" : "no",
	    "general.Performance.3" : "unlimited",				# Max Simultaneous TCP Sessions Per Host
	    "general.Performance.4" : "unlimited",				# Max Simultaneous TCP Sessions Per Scan
	    "preferences.Service+Detection.130" : "All",			#ssl check on all ports
	    "Filedata.Nmap+(%s)."%(policy_name.replace(" ", "+")) : os.path.basename(filename),
	    "preferences.Nmap+(%s).274"%(policy_name.replace(" ","+")) : os.path.basename(filename),
	 
	}
	policy = json.loads(x.createPolicy(policy_name, os.path.basename(filename), policy_settings))
        if policy["reply"]["status"] != "OK":
             print "[!] An error occured while creating the policy."
        else:
            print "[$] Policy successfully created."
	    print "[+] Creating new scan ..."
	    scan = x.scanNew("%s - full TCP, UDP top 1000"%(projectname), targets, policy["reply"]["contents"]["metadata"]["id"])
	    if "error" in scan:
                print "[!] An error occured when launching the scan."
            else:
                print "[$] Scan %s has been launched ! Results will be available at https://%s:%d/html5.html#/scans/%s"%(scan["uuid"], server, port, scan["uuid"])
    else:
        print "[!] An error occured while uploading the file."
 
    x.logout()
else:
    print "Usage: %s targets_file project_name config_file"%(sys.argv[0])

