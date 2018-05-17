#!/bin/python

import urllib2, socket
from urlparse import urlparse

class SecurityHeaderVerifier(object):
	__security_headers = { "content-security-policy":   ["Not Found", ["default-src", "script-src", "connect-src", "img-src", "style-src"], 5, "Not Secure", "content-security-policy: default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self';"],
						   "x-xss-protection":          ["Not Found", ["1", "mode", "block"], 3, "Not Secure", "x-ss-protection: 1; mode=block"],
						   "strict-transport-security": ["Not Found", ["max-age", "includeSubDomains"], 2, "Not Secure", "strict-transport-security: max-age=YOUR MAX AGE; includeSubDomains"],
						   "x-frame-options":           ["Not Found", ["DENY"], 1, "Not Secure", "x-frame-options: DENY"],
						   "public-keys-pins":          ["Not Found", ["pin-sha256","max-age", "includeSubDomains", "report-uri"], 5, "Not Secure", "Public-Key-Pins: pin-sha256=PRIMARY_KEY; pin-sha256=BACKUP_KEY; max-age=PIN_CACHE_EXPIRE_TIME; includeSubdomains; report-uri=YOUR_SITE_TO_REPORT"],
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
		for key in self.__security_headers:
			print "%s: %s, %s" % (key, self.__security_headers[key][0], self.__security_headers[key][3])

	def show_not_found_header_info(self):
		for key in self.__security_headers:
			if self.__security_headers[key][3] == "Not Secure":
				print "FOR %s IT'S RECOMMENDED => %s" % (key, self.__security_headers[key][4])

	def verify_url(self, url):
		try:
			header = {"User-Agent":"Mozilla/5.0"}
			req = urllib2.Request(url, headers=header)
			content = urllib2.urlopen(req, timeout = 2)
			ip = socket.gethostbyname(urlparse(content.geturl()).hostname)
			info = content.info()
			request_url = content.geturl()

			print "URL: %s" % request_url
			print "IP: %s\n\nSECURITY HEADERS" % ip
			self.check_headers(info)
			self.show_verified_headers()
			print "--------------------------"
			self.show_not_found_header_info()
			print "\nRAW HEADERS\n%s" % info
			return True

		except (urllib2.URLError, ValueError):
			return False

	def do_search(self, string):
		protocol = [" ", "https://", "http://"]

		for index in range(len(protocol)):
			if self.verify_url("%s%s" % (protocol[index], string)):
				break
			elif index == 2:
				print "Page Not Found."


