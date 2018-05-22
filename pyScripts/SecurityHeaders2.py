#!/bin/python

import urllib2, socket, sys
from urlparse import urlparse, urlunparse, urlsplit, urlunsplit

class Verifier(object):

	def get_raw_headers(self, content):
		info = content.info()
		
		return info

	def get_web_content(self, string):
		try:
			parse = urlparse(string)
			string = parse._replace(scheme="https")
			url = urlunparse(string).replace(":///", "://")
			header = {"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36"}
			request = urllib2.Request(url, headers = header)
			content = urllib2.urlopen(request, timeout=2)

			#ip = socket.gethostbyname(urlparse(content.geturl()).hostname)
			#url = content.geturl()
			#info = content.info()
			return content
		except urllib2.URLError:
			return False


