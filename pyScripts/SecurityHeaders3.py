#!/bin/python

import urllib2, socket
from urlparse import urlparse, urlunparse

def __replace_scheme(string, protocol):
        parse = urlparse(string)
        parse = parse._replace(scheme=protocol)
        url = urlunparse(parse).replace(":///", "://")
        return url

def __check_url(url, protocol):
	new_url = __replace_scheme(url, protocol)
	agent_header = {"User-Agent":"Mozilla"}
	request = urllib2.Request(new_url, headers=agent_header)
	try:
		data = urllib2.urlopen(request, timeout=3)
	except:
		data = None
	return data

def __get_content(self, url):
	data = 

content = __check_url("google.com", "https://")
