#!/usr/bin/python

"""
Copyright (c) 2010 HomeAway, Inc.
All rights reserved.  http://www.homeaway.com

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import sys,subprocess,shlex,os,smtplib,logging
import xml.etree.ElementTree

from NessusXMLRPC import Scanner
from optparse import OptionParser
from random import randint
from time import sleep
from logging.handlers import WatchedFileHandler
from datetime import datetime

from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import Encoders

#
# Modify these strings to suit your environment
#

logfile = "nessus.log"			# Log file. Nuff said.

xslt = "reports/html.xsl"		# XSL used in rendering the HTML report from XML
xsltproc = "/usr/bin/xsltproc"		# Location of xslt tool on Linux ;-)

myserver = "myserver"			# Lazy, less typing measure
myuser = "myuser"			# Lazy, less typing measure
mypass = "mypass"			# Lazy, less typing measure
myemail = "myemail"			# Lazy, less typing measure
myfrom = "myfrom"			# Laxy, less typing measure
mysmtp = "mysmtp"			# Yup, another one...

devnull = open('/dev/null','w')		# A void for safely redirecting and dumping stuff I don't want

# Setup some basic logging. After all, this will hopefully be automated...
logger = logging.getLogger('Nessus')
logger.setLevel(logging.DEBUG)
handler = WatchedFileHandler( logfile )
logger.addHandler(handler)

def info( msg ):
	"""
	Provide some very simple logging.

	@type	msg:	string
	@param	msg:	Info message to be written to the log.
	"""
	logger.info( "%s %s" % (datetime.now(),msg))

def generate_report( data, xmlfile, htmlfile ):
	"""
	Simple method for transforming the XML spit out by the server into report-style HTML using
	what's available.

	@type	data:		string
	@param	data:		XML output from the report of a scan.
	@type	xmlfile:	string
	@param	xmlfile:	The file where the XML is to be output.
	@type	htmlfile:	string
	@type	htmlfile:	The file where the HTML is to be output.
	"""
	output = open( xmlfile, "w")
        output.write(data)
        output.close()
        # Transform the XML using the XSL provided by Nessus for HTML reports (quietly)
        subprocess.call(shlex.split("%s %s %s -o %s" % (xsltproc,xslt,xmlfile,htmlfile)), stdout=devnull, stderr=devnull)

def generate_summary( data ):
	"""
	Generate a simple summary as the contents of the email report to be sent.

	@type	data:	string
	@param	data:	XML data from the current report.
	"""
	severity = { '0' : 0,
                     '1' : 0,
                     '2' : 0,
                     '3' : 0 }
	prefs = {}
	pref = None
	count = 0
	
	parsed = xml.etree.ElementTree.fromstring(data)

	# Pull out the report name
	report = parsed.find("Report").attrib['name']

	# Pull out the name of the policy used
	policy = parsed.find("Policy/policyName").text

	# Parse preferences and construct a dict from all settings
	for preference in parsed.find("Policy/Preferences").getiterator("preference"):
		for child in preference.getchildren():
			if child.tag == 'name':
				prefs[child.text] = None
				pref = child.text
			elif child.tag == 'value':
				prefs[pref] = child.text
	# Parse severity for totals
	for host in parsed.find("Report").getiterator("ReportHost"):
                for item in host.getiterator("ReportItem"):
                        severity[item.attrib['severity']] += 1

	return "Scan Name: %25s\nTarget(s): %25s\nPolicy: %28s\n\nRisk Summary\n%s\n%15s %3s\n%15s %3s\n%15s %3s\n\n%15s %3s" % ( report, prefs['TARGET'], policy,'-'*36,'High', severity['3'], 'Medium', severity['2'], 'Low', severity['1'], 'Open Ports', severity['0'])


def send_report( to, subject, body, attachment):
	"""
	Send the email report to its destination.

	@type	to:		string
	@param	to:		Destination email address for the report.
	@type	subject:	string
	@param	subject:	The subject of the email message.
	@type	body:		string
	@param	body:		The body of the email message (includes report summary).
	@type	attachment:	string
	@param	attachment:	Path to report file for attaching to message.
	"""
	message = MIMEMultipart()
	message['From'] = "Nessus Scanner <%s>" % myfrom
	message['To'] = to
	message['Subject'] = subject

	message.attach( MIMEText( body ))
	part = MIMEBase('application','text/html')
	part.set_payload( open( attachment, 'r').read())
	Encoders.encode_base64(part)
	part.add_header('Content-Disposition','attachment; filename="%s"' % os.path.basename(attachment))
	message.attach(part)

	conn = smtplib.SMTP(mysmtp)
	conn.sendmail( message['From'], to, message.as_string())
	conn.close()

if __name__ == "__main__":
	"""
	Nessus Command-line Rewrite
	------------------------------

	The goal with this tool is to essentially replace the command-line versions of the Nessus scanner. I
	found with the latest version that they've deprecated version 1 of the Nessus XML output preventing
	policies exported directly through the web interface from being used with the command-line versions to
	automate scans. This tool is an example using the NessusXMLRPC module I've also written to completely
	automate scans using the Nessus server. It also sends email summaries and reports. For further info,
	simply run the command without any arguments or examine the output below:

	kurtis@ubuntu:~/assess/tools/nessus-xmlrpc$ ./nessus.py 
	Usage: nessus.py [options]
	
	Options:
	  -h, --help            show this help message and exit
	  -s SERVER, --server=SERVER
	                        Nessus server to use
	  -p PORT, --port=PORT  web (XMLRPC) interface port on Nessus server
	  -u USER, --user=USER  Nessus user account
	  -x PASSWORD, --password=PASSWORD
	                        Nessus user account password
	  -t TARGET, --target=TARGET
	                        target string for Nessus scan
	  -n NAME, --name=NAME  name for the scan
	  -l POLICY, --policy=POLICY
	                        policy (on server-side) to use in the scan
	  -f INFILE, --file=INFILE
	                        input file with multiple scans to run
	  -o REPORTS, --output=REPORTS
	                        default folder for outputting reports
	  -e EMAIL, --email=EMAIL
	                        email address for sending the transformed reports
	kurtis@ubuntu:~/assess/tools/nessus-xmlrpc$ 

	nessus.py and NessusXMLRPC were written under Python v2.6.5 with xsltproc available in the PATH. Also,
	be careful when running several concurrent scans. I've had the Nessus server lockup with six concurrent
	scans to where I needed to bounce the box.

	All code has been written by Kurtis Miller.
	"""
	parser = OptionParser()
	parser.add_option("-s", "--server", dest='server', default=myserver, help="Nessus server to use")
	parser.add_option("-p", "--port", dest='port', default=8834, help="web (XMLRPC) interface port on Nessus server")
	parser.add_option("-u", "--user", dest='user', default=myuser, help="Nessus user account")
	parser.add_option("-x", "--password", dest='password', default=mypass, help="Nessus user account password")

	parser.add_option("-t", "--target", dest='target', help="target string for Nessus scan")
	parser.add_option("-n", "--name", dest='name', default="No-name Auto Scan", help="name for the scan")
	parser.add_option("-l", "--policy", dest='policy', help="policy (on server-side) to use in the scan")
	parser.add_option("-f", "--file", dest='infile', help="input file with multiple scans to run")
	parser.add_option("-o", "--output", dest='reports', default="reports", help="default folder for outputting reports")
	parser.add_option("-e", "--email", dest='email', default=myemail, help="email address for sending the transformed reports")

	(options,args) = parser.parse_args()
	
	if 	options.server is not None and \
		options.user is not None and \
		options.password is not None:
        	
		if options.infile is not None:
			info("Nessus scanner started with input file (list of scans).")
			x = Scanner( options.server, options.port, options.user, options.password )
			scans = []
			complete = False
			f = open(options.infile, "r")
			for line in f:
				line = line.strip().split(':')
				scan = x.quickScan( line[0], line[1], line[2] )
				scans.append(scan)
				info("Scan successfully started. Owner: %s, Name: %s" % (scan['owner'],scan['scan_name']))
			# Monitor for completion of the scans
			scancount = len(scans)
			count = scancount
			while count != 0:
				count = scancount
				sleeptime = randint(5,30)
				info("Polling for scan completion (sleeping %d seconds)" % sleeptime)
				sleep(sleeptime)
				reports = x.reportList()
				for scan in scans:
					for report in reports:
						if report['status'] == 'completed' and scan['uuid'] == report['name']:
							count -= 1
			# Get reports for each scan and store them on disk for emailing later
			for scan in scans:
				data = x.reportDownload( scan['uuid'] )
				xmlfile = options.reports + "/" + scan['scan_name'].replace(' ','') + ".xml"
				htmlfile = options.reports + "/" + scan['scan_name'].replace(' ','') + ".html"
				generate_report( data, xmlfile, htmlfile )
				info("XML report saved as %s" % xmlfile)
                        	info("HTML report saved as %s" % htmlfile)

				# Put together the text of the email with the report attached
	                        send_report( options.email, "Nessus Scan Report: %s" % scan['scan_name'], generate_summary(data), htmlfile)
	                        info("Email report sent")

			x.logout()
				
		elif 	options.name is not None and \
			options.target is not None and \
			options.policy is not None:
			
			info("Nessus scanner started with a single scanning target.")
			x = Scanner( options.server, options.port, options.user, options.password )
			scan = x.quickScan( options.name, options.target, options.policy )
			info("Scan successfully started. Owner: %s, Name: %s" % (scan['owner'],scan['scan_name']))

			# Poll for completion of the scan
			complete = False
			while complete != True:
				sleeptime = randint(5,30)
				info("Polling for scan completion (sleeping %d seconds)" % sleeptime)
	                        sleep(sleeptime)
				reports = x.reportList()
				for report in reports:
					if report['status'] == 'completed' and scan['uuid'] == report['name']:
						info("Scan complete. Name: %s, UUID: %s" % (scan['scan_name'],scan['uuid']))
						complete = True
	
			# Get report for scan and email it
			data = x.reportDownload( scan['uuid'] )
			xmlfile = options.reports + "/" + scan['scan_name'].replace(' ','') + ".xml"
			htmlfile = options.reports + "/" + scan['scan_name'].replace(' ','') + ".html"
			generate_report( data, xmlfile, htmlfile )
			info("XML report saved as %s" % xmlfile)
			info("HTML report saved as %s" % htmlfile)


			send_report( options.email, "Nessus Scan Report: %s" % scan['scan_name'], generate_summary(data), htmlfile)
			info("Email report sent")
	        	x.logout()
	        else:
			parser.print_help()
	sys.exit(0)
