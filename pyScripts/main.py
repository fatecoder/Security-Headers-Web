#!/bin/ptyhon

from SecurityHeadersConsole import SecurityHeaderVerifier
import sys

secure = SecurityHeaderVerifier()

try:
	secure.do_search(sys.argv[1])
except IndexError:
	print "Input an URL in command line"
