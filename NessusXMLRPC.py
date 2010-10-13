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

import sys
import xml.etree.ElementTree

from httplib import HTTPSConnection,CannotSendRequest,ImproperConnectionState
from urllib import urlencode
from random import randint
from time import sleep

class Scanner:
	def __init__( self, host, port, login=None, password=None):
		"""
		Initialize the scanner instance by setting up a connection and authenticating
		if credentials are provided. 

		@type	host:		string
		@param	host:		The hostname of the running Nessus server.
		@type	port:		number
		@param	port:		The port number for the XMLRPC interface on the Nessus server.
		@type	login:		string
		@param	login:		The username for logging in to Nessus.
		@type	password:	string
		@param	password:	The password for logging in to Nessus.
		"""
		self.host = host
		self.port = port
		self.connection = self._connect( host, port )
		self.headers = {"Content-type":"application/x-www-form-urlencoded","Accept":"text/plain"}

		if login != None and password != None:
			self.login( login, password )
	
	def _connect( self, host, port ):
		"""
		Internal method for connecting to the target Nessus server.

		@type	host:	string
		@param	host:	The hostname of the running Nessus server.
		@type	port:	number
		@param	port:	The port number for the XMLRPC interface on the Nessus server.
		"""
		self.connection = HTTPSConnection( host, port )

	def _request( self, method, target, params ):
		"""
		Internal method for submitting requests to the target Nessus server, rebuilding
		the connection if needed.

		@type	method:	string
		@param	method:	The HTTP verb/method used in the request (almost always POST).
		@type	target:	string
		@param	target:	The target path (or function) of the request.
		@type	params:	string
		@param	params:	The URL encoded parameters used in the request.
		"""
		try:	
			if self.connection is None:
				self._connect( self.host, self.port )
				self.login( self.login, self.password)
			self.connection.request( method, target, params, self.headers )
		except CannotSendRequest,ImproperConnectionState:
			self._connect( self.host, self.port)
			self.login( self.login, self.password )
			self._request( method, target, params, self.headers )
		return self.connection.getresponse().read().replace("\n",'')

	def login( self, login, password, seq=randint(1000,9999) ):
		"""
		Log in to the Nessus server and preserve the token value for subsequent requests.

		@type	login:		string
		@param	login:		The username for logging in to Nessus.
		@type	password:	string
		@param	password:	The password for logging in to Nessus.
		@type	seq:		number
		@param	seq:		A sequence number that will be echoed back for unique identification (optional).
		"""
		self.username = login
		self.password = password

                params = urlencode({ 'login':self.username, 'password':self.password, 'seq':seq})
		response = self._request( "POST", "/login", params )
                
		#print "Sent to Parser: %s" % response
		parsed = xml.etree.ElementTree.fromstring(response)
		if parsed.find("status").text == "OK":
			#print "Login succeeded."
			self.token = parsed.find("contents/token").text
			#print "Token value: %s" % self.token
			self.headers["Cookie"] = "token=%s" % self.token

	def logout( self, seq=randint(1000,9999) ):
		"""
		Log out of the Nessus server, invalidating the current token value.

		@type	seq:	number
		@param	seq:	A sequence number that will be echoed back for unique identification (optional).
		"""
		params = urlencode( {'seq':seq} )
		response = self._request( "POST", "/logout", params)
		
	def policyList( self, seq=randint(1000,9999) ):
		"""
		List the current policies configured on the server and return a dict with the info.

		@type	seq:	number
		@param  seq:    A sequence number that will be echoed back for unique identification (optional).
		"""
		policies = []
		count = 0

		params = urlencode( {'seq':seq} )
		response = self._request( "POST", "/policy/list", params)

		parsed = xml.etree.ElementTree.fromstring(response)
		if parsed.find("status").text == "OK":
			for policy in parsed.find("contents/policies").getiterator("policy"):
				# Look at each policy
				if len(policies) == count:
					policies.append({})
				for element in policy.getchildren():
					policies[count][element.tag] = element.text
				count += 1
		return policies

	def scanNew( self, scan_name, target, policy_id, seq=randint(1000,9999)):
		"""
		Start up a new scan on the Nessus server immediately.

		@type	scan_name:	string
		@param	scan_name:	The desired name of the scan.
		@type	target:		string
		@param	target:		A Nessus-compatible target string (comma separation, CIDR notation, etc.)
		@type	policy_id:	number
		@param	policy_id:	The unique ID of the policy to be used in the scan.
		@type	seq:		number
		@param	seq:		A sequence number that will be echoed back for unique identification (optional).
		"""
		scan = {}

		params = urlencode( {'target':target,'policy_id':policy_id,'scan_name':scan_name,'seq':seq} )
		response = self._request( "POST", "/scan/new", params)

		parsed = xml.etree.ElementTree.fromstring(response)
		if parsed.find("status").text == "OK":
			# Return what you can about the scan.
			for element in parsed.find("contents/scan").getchildren():
				scan[element.tag] = element.text
			return scan

	def quickScan( self, scan_name, target, policy_name, seq=randint(1000,9999)):
		"""
		Configure a new scan using a canonical name for the policy. Perform a lookup for the policy ID and configure the scan,
		starting it immediately.

		@type	scan_name:	string
		@param  scan_name:      The desired name of the scan.
                @type   target:         string
                @param  target:         A Nessus-compatible target string (comma separation, CIDR notation, etc.)
                @type   policy_name:    string
                @param  policy_name:    The name of the policy to be used in the scan.
                @type   seq:            number
                @param  seq:            A sequence number that will be echoed back for unique identification (optional).
		"""
		for policy in self.policyList():
			if policy['policyName'] == policy_name:
				policy_id = policy['policyID']
		return self.scanNew( scan_name, target, policy_id )

	def reportList( self, seq=randint(1000,9999)):
		"""
		Generate a list of reports available on the Nessus server.

		@type   seq:            number
                @param  seq:            A sequence number that will be echoed back for unique identification (optional).
		"""
		reports = []
		count = 0

		params = urlencode({'seq':seq})
		response = self._request( "POST", "/report/list", params)

		parsed = xml.etree.ElementTree.fromstring(response)
		if parsed.find("status").text == "OK":
			for report in parsed.find("contents/reports").getiterator("report"):
				if len(reports) == count:
					reports.append({})
				for element in report.getchildren():
					reports[count][element.tag] = element.text
				count += 1
		return reports

	def reportDownload( self, report ):
		"""
		Download a report (XML) for a completed scan.

		@type	report:	string
		@param	report:	The UUID of the report or completed scan.
		"""
		params = urlencode({'report':report})
		return self._request( "POST", "/file/report/download", params )
