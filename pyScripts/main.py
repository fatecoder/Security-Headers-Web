#!/bin/ptyhon

from SecurityHeaders import Verifier
import sys

secure = Verifier()

def print_info(list):
	print list[0]
	print list[1]
	for key in list[2]:
		print "%s: %s" % (key, list[2][key])
	secure.check_headers(list[2])

url = secure.replace_scheme(sys.argv[1],"https")
content = secure.check_url(url)
if content:
	info = secure.get_all_info(content)
	print_info(info)
else:
	url = secure.replace_scheme(sys.argv[1],"http")
	content = secure.check_url(url)
	if content:
		info = secure.get_all_info(content)
		print_info(info)
	else:
		print "PAGE NOT FOUND"
