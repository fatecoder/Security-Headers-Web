#!/bin/ptyhon

from SecurityHeaders import Verifier
import sys

secure = Verifier()

info = secure.get_info(sys.argv[1])

if info:
	ip = info[0]
	url = info[1]
	headers = info[2]
	checked_headers = []
	for key in headers:
		header_status = secure.check_header(key, headers[key])
		if header_status:
			print "%s: %s |=> %s!!!" % (key, headers[key], header_status)
			checked_headers.append(key)
else:
	print "PAGE NOT FOUND"


