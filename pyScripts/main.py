#!/bin/python

from SecurityHeaders import Verifier
from colorama import Fore, init
import sys, requests

init(autoreset=True)
verifier = Verifier()

def print_info(list_info):
	security = verifier.check_headers(list_info[2])
	print "URL: %s" % list_info[0]
	print "IP address: %s" % list_info[1]
	print "---------HEADERS---------"
	for header in security:
		status = security[header]["status"]
		if status == "SECURE":
			print "%s%s: %s" % (Fore.GREEN, header, security[header]["value"])
		elif status == "WARNING":
			print "%s%s: %s RECOMMENDED %s" % (Fore.YELLOW, header, security[header]["value"], security[header]["recommended"])
		else:
			print "%s%s: %s. RECOMMENDED %s" % (Fore.RED, header, security[header]["value"], security[header]["recommended"])
	print "---------RAW HEADERS---------"
	for header in list_info[2]:
		print "%s: %s" % (header, list_info[2][header])

list_info = verifier.get_page_info(sys.argv[1])
if list_info != None:
	print_info(list_info)
else:
	print "PAGE NOT FOUND"
