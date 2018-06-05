#!/bin/python

from SecurityHeaders2 import Verifier
from colorama import Fore, init
import sys, requests

init(autoreset=True)
verifier = Verifier()

def print_info(list_info):
	url = list_info[0]
	ip = list_info[1]
	raw_headers = list_info[2]
	security_headers = list_info[3]
	print "URL: %s" % url
	print "IP address: %s" % ip
	print "---------HEADERS---------"
	for header in security_headers:
		if header.status == "SECURE":
			print "%s%s: %s" % (Fore.GREEN, header.name, header.value)
		elif header.status == "WARNING":
			print "%s%s: %s RECOMMENDED %s" % (Fore.YELLOW, header.name, header.value, header.recommended)
		else:
			print "%s%s: %s. RECOMMENDED %s" % (Fore.RED, header.name, header.value, header.recommended)
	print "---------RAW HEADERS---------"
	for header in raw_headers:
		print "%s: %s" % (header, raw_headers[header])

list_info = verifier.get_page_info(sys.argv[1])

if list_info != None:
	print_info(list_info)
else:
	print "PAGE NOT FOUND"
