#!/bin/python

from SecurityHeaders import Verifier
from colorama import Fore, init
import sys, requests

init(autoreset=True)
secure = Verifier() #

def print_info(list_info):
	headers = secure.check_headers(list_info[3])
	print "URL: %s" % list_info[0]
	print "IP address: %s" % list_info[1]
	print "Report Date: %s" % list_info[2]
	print "---------HEADERS---------"
	for element in headers:
		if "SECURE" in element:
			print Fore.GREEN + element
		elif "WARNING" in element:
			print Fore.YELLOW + element
		else:
			print Fore.RED + element
	print "---------RAW HEADERS---------"
	for key in list_info[3]:
		print "%s: %s" % (key, list_info[3][key])

list_info = secure.get_page_info(sys.argv[1])
print_info(list_info)

