#!/bin/ptyhon

from SecurityHeaders import Verifier
from colorama import Fore, Back, init
import sys

init(autoreset=True)
secure = Verifier()

def print_info(list):
	headers = secure.check_headers(list[2])
	print "URL: %s" % list[0]
	print "IP address: %s" % list[1]
	print "---------HEADERS---------"
	for element in headers:
		if "SECURE" in element:
			print "%s%s\n" % (Fore.GREEN, element)
		elif "WARNING" in element:
			print "%s%s\n" % (Fore.YELLOW, element)
		else:
			print "%s%s\n" % (Fore.RED, element)
	print "---------RAW HEADERS---------"
	for key in list[2]:
		print "%s: %s" % (key, list[2][key])

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
