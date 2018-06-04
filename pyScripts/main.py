#!/bin/python

from SecurityHeaders import Verifier
from colorama import Fore, init
import sys, requests

init(autoreset=True)
verifier = Verifier() #

def print_info(list_info):
	headers = verifier.check_headers(list_info[2])
	print "URL: %s" % list_info[0]
	print "IP address: %s" % list_info[1]
	print "---------HEADERS---------"
	for element in headers:
		if "SECURE" in element:
			print Fore.GREEN + element
		elif "WARNING" in element:
			print Fore.YELLOW + element
		else:
			print Fore.RED + element
	print "---------RAW HEADERS---------"
	for key in list_info[2]:
		print "%s: %s" % (key, list_info[2][key])

list_info = verifier.get_page_info(sys.argv[1])
if list_info != None:
	print_info(list_info)
else:
	print "PAGE NOT FOUND"
