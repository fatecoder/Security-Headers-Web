#!/bin/python

import urllib2, socket, time
from urlparse import urlparse, urlunparse

class Verifier(object):

	__security_headers = {  "content-security-policy":[["upgrade-insecure-request"], "upgrade-insecure-request"],
							"x-xss-protection":[["1;", "mode=block"],"1; mode=block"],
							"strict-transport-security":[["max-age", "includeSubDomains"],"max-age=YOUR_MAX_AGE; includeSubDomains"],
							"x-frame-options":[["DENY"], "DENY"],
							"x-content-type-options":[["nosniff"], "nosniff"],
							"set-cookie":[["Secure", "HttpOnly"], "COOKIE_NAME=COOKIE_VALUE; Secure; HttpOnly"],
							"referrer-policy":[["no-referrer-when-downgrade"],"no-referrer-when-downgrade"] }

	def __init__(self, name=None, status=None, value=None, recommended=None):
		self.name = name
		self.status = status
		self.value = value
		self.recommended = recommended

	def __cookie_values(self, values):
		filtered_values = ""
		for value in self.__security_headers["set-cookie"][0]: # quitar
			if value in values:
				filtered_values += "%s; " % value
		return filtered_values[:-2] #

	def __check_headers(self, raw_headers):
		security_list = []
		keys = self.__security_headers.keys()
		for header in keys:
			recommended = self.__security_headers[header][1]
			if header in raw_headers:
				#
				status = self.__get_header_status(header, raw_headers[header])
				value = raw_headers[header] #
				if header == "set-cookie":
					value = self.__cookie_values(value)
				security_list.append(Verifier(header, status, value, recommended))
			else:
				security_list.append(Verifier(header, "NOT_FOUND", "EMPTY", recommended))
		return security_list

	def __get_header_status(self, key, value): #cambiar a header
		directives = self.__security_headers[key][0]
		total_directives = len(directives)
		total = 0
		for attrib in directives:
			if attrib in value: # revisar
				total = total + 1 #
		return "WARNING" if total != total_directives else "SECURE" # revisar

	#acomodar funcs
	def get_page_info(self, url):
		headers = {}
		content = self.__get_content(url)
		if content != None:
			url = content.geturl()
			ip = socket.gethostbyname(urlparse(url).hostname)
			for header in content.info():
				headers[header] = content.info()[header]
			security_headers = self.__check_headers(headers)
			return [url, ip, headers, security_headers]

	def __get_content(self, url):
		data = self.__check_url(url, "https") if self.__check_url(url, "https") else self.__check_url(url, "http")
		if data is False: # quitar
			data = None
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
		#return ever

	def replace_scheme(self, string, protocol):
		parse = urlparse(string)
		new_string = parse._replace(scheme=protocol) # cambiar nombre de variable
		url = urlunparse(new_string).replace(":///", "://")
		return url

