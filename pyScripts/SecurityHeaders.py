#!/bin/python

import urllib2, socket, sys
from urlparse import urlparse, urlunparse, urlsplit, urlunsplit

class Verifier(object):

	__security_headers = {  "content-security-policy":["default-src", "script-src", "connect-src", "img-src", "style-src"],
							"x-xss-protection":["1;", "mode=block"],
							"strict-transport-security":["max-age", "includeSubDomains"],
							"x-frame-options":["DENY"],
							"public-keys-pins":["pin-sha256","max-age", "includeSubDomains", "report-uri"],
							"x-content-type-options":["nosniff"]}

	def check_header(self, header, values):
		if header in self.__security_headers:
			return self.__check_header_status(header, values)

	def __check_header_status(self, header, values):
		status = "SECURE"
		for element in self.__security_headers[header]:
			if element not in values:
				status = "WARNING"
				break
		return status

	def get_info(self, string):
		try:
			headers = {}
			parse = urlparse(string)
			string = parse._replace(scheme="https")
			url = urlunparse(string).replace(":///", "://")
			agent_header = {"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36"}
			request = urllib2.Request(url, headers=agent_header)
			content = urllib2.urlopen(request, timeout=5)
			info = content.info()

			ip = socket.gethostbyname(urlparse(content.geturl()).hostname)
			url = content.geturl()
			for key in info:
				headers[key] = info[key]

			return [ip, url, headers]
		except urllib2.URLError:
			return False


