#!/bin/ptyhon

from SecurityHeaders import Verifier
import sys

secure = Verifier()

def print_info(list):
	print list[0]
	print list[1]
	for key in list[2]:
		print "%s: %s" % (key, list[2][key])
	print "---------"
	#print secure.check_headers(list[2])
	headers = secure.check_headers(list[2])
	for element in headers:
		print element


url = secure.replace_scheme(sys.argv[1],"https")
content = secure.get_all_info(url)
if content:
	print_info(content)
else:
	url = secure.replace_scheme(sys.argv[1],"http")
	content = secure.get_all_info(url)
	if content:
		print_info(content)
	else:
		print "PAGE NOT FOUND"

