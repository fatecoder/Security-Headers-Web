#!/bin/python

import urllib2, socket, sys
from urlparse import urlparse, urlunparse

class Verifier(object):

	__security_headers = {  "content-security-policy":[["default-src", "script-src", "connect-src", "img-src", "style-src"], "default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self';"],
							"x-xss-protection":[["1;", "mode=block"],"1; mode=block"],
							"strict-transport-security":[["max-age", "includeSubDomains"],"max-age=YOUR MAX AGE; includeSubDomains"],
							"x-frame-options":[["DENY"], "DENY"],
							"public-keys-pins":[["pin-sha256","max-age", "includeSubDomains", "report-uri"], "pin-sha256=PRIMARY_KEY; pin-sha256=BACKUP_KEY; max-age=PIN_CACHE_EXPIRE_TIME; includeSubDomains; report-uri=YOUR_SITE_TO_REPORT"],
							"x-content-type-options":[["nosniff"], "nosniff"] }

	def check_headers(self, headers):
		list = []
		for key in self.__security_headers:
			r = self.__security_headers[key][1]
			if self.__security_headers[key][0] in headers[key]:
				status = self.__check_header_values(key, headers[key])
				#print "%s: %s |=> %s" % (key, headers[key], status)
				if status == "WARNING":
					list.append("%s: %s |=> %s $ %s" % (key, headers[key], status, r))
				else:
					list.append("%s: %s |=> %s" % (key, headers[key], status))
					print status
			else:
				headers.append("%s |=> NOT FOUND $ %s" % (key, r))
		return headers

	def __check_header_values(self, key, value):
		status = "SECURE"
		for attrib in self.__security_headers[key][0]:
			if attrib not in value:
				status = "WARNING"
				break
		return status

	def get_all_info(self, string):
		try:
			raw_headers = {}
			agent_header = {"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36"}
			request = urllib2.Request(string, headers=agent_header)
			content = urllib2.urlopen(request, timeout=3)

			info = content.info()
			url = content.geturl()
			ip = socket.gethostbyname(urlparse(url).hostname)
			for key in info:
				raw_headers[key] = info[key]
			return [ip, url, raw_headers]
		except:
			return False

	def replace_scheme(self, string, protocol):
		parse = urlparse(string)
		new_string = parse._replace(scheme=protocol)
		url = urlunparse(new_string).replace(":///", "://")
		return url

