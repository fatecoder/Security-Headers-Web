#!/bin/python

import urllib2, socket
from urlparse import urlparse, urlunparse

class SecurityHeaders(object):

	class HeaderInfo(object):
		def __init__(self, name, status, value, recommended):
			self.name = name
			self.status = status
			self.value = value
			self.recommended = recommended

	x_xss_protection = HeaderInfo("x-xss-protection", "status", "value", "recommended")
