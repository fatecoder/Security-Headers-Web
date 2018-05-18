#!/bin/python

import urllib2, socket
from urlparse import urlparse

class SecurityHeaderVerifier(object):
	__security_headers = { "content-security-policy":   ["Not Found", ["default-src", "script-src", "connect-src", "img-src", "style-src"], 5, "Not Secure", "content-security-policy: default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self';"],
						   "x-xss-protection":          ["Not Found", ["1", "mode", "block"], 3, "Not Secure", "x-ss-protection: 1; mode=block"],
						   "strict-transport-security": ["Not Found", ["max-age", "includeSubDomains"], 2, "Not Secure", "strict-transport-security: max-age=YOUR MAX AGE; includeSubDomains"],
						   "x-frame-options":           ["Not Found", ["DENY"], 1, "Not Secure", "x-frame-options: DENY"],
						   "public-keys-pins":          ["Not Found", ["pin-sha256","max-age", "includeSubDomains", "report-uri"], 5, "Not Secure", "Public-Key-Pins: pin-sha256=PRIMARY_KEY; pin-sha256=BACKUP_KEY; max-age=PIN_CACHE_EXPIRE_TIME; includeSubDomains; report-uri=YOUR_SITE_TO_REPORT"],
						   "x-content-type-options":    ["Not Found", ["nosniff"], 1, "Not Secure", "x-content-type-options: nosniff"] }

	def check_headers(self, info):
		for key in info:
			if key in self.__security_headers:
				accum = 0
				self.__security_headers[key][0] = "Found"
				for attrib in self.__security_headers[key][1]:
					if attrib in info[key]:
						accum += 1
					if accum == self.__security_headers[key][2]:
						self.__security_headers[key][3] = "Secure"

	def show_verified_headers(self):
		dictionary_status = {}
		for key in self.__security_headers:
			item1 = key
			item2 = self.__security_headers[key][0]
			item3 = self.__security_headers[key][3]
			dictionary_status[item1] = [item2, item3]
		return dictionary_status

	def show_not_found_header_info(self):
		dictionary_info = {}
		for key in self.__security_headers:
			if self.__security_headers[key][3] == "Not Secure":
				dictionary_info[key] = self.__security_headers[key][4]
		return dictionary_info

	def verify_url(self, url):
		try:
			header = {"User-Agent":"Mozilla/5.0"}
			req = urllib2.Request(url, headers=header)
			content = urllib2.urlopen(req, timeout = 3).info()
			ip = socket.gethostbyname(urlparse(content.geturl()).hostname)
			info = content.info()
			request_url = content.geturl()
			return True

		except (urllib2.URLError, ValueError):
			return False

	def do_search(self, string):
		protocols = [" ", "https://", "http://"]

		for element in protocols:
			if self.verify_url(string):
				print "OK %s" % element
				break
			else:
				print "Not Found"
