#!/bin/ptyhon

from SecurityHeaders import SecurityHeaderVerifier
import sys

secure = SecurityHeaderVerifier()

try:
	secure.do_search(sys.argv[1])
except ValueError as e:
	print "Input an URL in command line."


