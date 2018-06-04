#!/bin/python

import urllib2, socket, time
from urlparse import urlparse, urlunparse

class Verifier(object):

	__security_headers = {  "content-security-policy":[["default-src 'self'"], "default-src 'self'"],
							"x-xss-protection":[["1;", "mode=block"],"1; mode=block"],
							"strict-transport-security":[["max-age", "includeSubDomains"],"max-age=YOUR_MAX_AGE; includeSubDomains"],
							"x-frame-options":[["DENY"], "DENY"],
							"public-keys-pins":[["pin-sha256","max-age", "includeSubDomains", "report-uri"], "pin-sha256=PRIMARY_KEY; pin-sha256=BACKUP_KEY; max-age=PIN_CACHE_EXPIRE_TIME; includeSubDomains; report-uri=YOUR_SITE_TO_REPORT"],
							"x-content-type-options":[["nosniff"], "nosniff"],
							"set-cookie":[["Secure", "HttpOnly"], "COOKIE_NAME=COOKIE_VALUE; Secure; HttpOnly"],
							"referrer-policy":[["no-referrer-when-downgrade"],"no-referrer-when-downgrade"] }

	def __cookie_security_values(self, cookies_values, secure):

		return 0

	def check_headers(self, raw_headers):
		list = []
		keys = self.__security_headers.keys()
		for value in keys:
			if value in raw_headers:
				status = self.__check_header_values(value, raw_headers[value])
				if status == "WARNING":
					list.append("%s %s RECOMMENDED %s" % (status, value, self.__security_headers[value][1]))
				else:
					list.append("%s %s: %s" % (status, value, raw_headers[value]))
			else:
				list.append("NOT-FOUND %s RECOMMENDED %s" % (value, self.__security_headers[value][1]))
		return list

	def __check_header_values(self, key, value):
		directives = self.__security_headers[key][0]
		total_directives = len(self.__security_headers[key][0])
		total = 0
		for attrib in directives:
			if attrib in value:
				total = total + 1
		return "WARNING" if total != total_directives else "SECURE"

	def get_page_info(self, url):
		headers = {}
		content = self.__get_content(url)
		if content != None:
			url = content.geturl()
			ip = socket.gethostbyname(urlparse(url).hostname)
			for header in content.info():
				headers[header] = content.info()[header]
			return [url, ip, headers]

	def __get_content(self, url):
		data = None
		#ternario
		data_https = self.__check_url(url, "https")
		data_http = self.__check_url(url, "http")
		if data_https:
			data = data_https
		elif data_http:
			data = data_http
		return data

	def __check_url(self, url, protocol):
		new_url = self.replace_scheme(url, protocol)
		agent_header = {"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36"}
		request = urllib2.Request(new_url, headers=agent_header)
		try:
			content = urllib2.urlopen(request, timeout=3)
			return content
		except:
			return False

	def replace_scheme(self, string, protocol):
		parse = urlparse(string)
		new_string = parse._replace(scheme=protocol)
		url = urlunparse(new_string).replace(":///", "://")
		return url
