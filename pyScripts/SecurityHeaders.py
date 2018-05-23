#!/bin/python

import urllib2, socket, sys
from urlparse import urlparse, urlunparse

class Verifier(object):

	__security_headers = {  "content-security-policy":["default-src", "script-src", "connect-src", "img-src", "style-src"],
							"x-xss-protection":["1;", "mode=block"],
							"strict-transport-security":["max-age", "includeSubDomains"],
							"x-frame-options":["DENY"],
							"public-keys-pins":["pin-sha256","max-age", "includeSubDomains", "report-uri"],
							"x-content-type-options":["nosniff"]}

	def check_headers(self, headers):
		for key in self.__security_headers:
			if key in headers:
				self.check_header_values(key, headers[key])
			else:
				print "%s |=> NOT FOUND" % key

	def check_header_values(self, key, value):
		print None

	def get_all_info(self, content):
		headers = {}
		info = content.info()
		url = content.geturl()
		ip = socket.gethostbyname(urlparse(url).hostname)
		for key in info:
			headers[key] = info[key]
		return [ip, url, headers]

	def check_url(self, string):
		try:
			agent_header = {"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36"}
			request = urllib2.Request(string, headers=agent_header)
			content = urllib2.urlopen(request, timeout=3)
			return content
		except:
			return False

	def replace_scheme(self, string, protocol):
		parse = urlparse(string)
		new_string = parse._replace(scheme=protocol)
		url = urlunparse(new_string).replace(":///", "://")
		return url

