#!/bin/python

from flask import Flask, request, render_template, Markup
from pyScripts.SecurityHeaders2 import Verifier

app = Flask(__name__)

verifier = Verifier()

def make_report_summary_table(security_headers):
	table = "<table class='report-table'><thead class='table-head-up'><tr><td colspan='3'>Report Summary</td></tr></thead>"\
			"<thead class='table-head-down'><tr><td>Security Header</td><td>Value</td><td>Recommended</td></tr></thead><tbody>"
	for header in security_headers:
		table += "<tr><td class='report-column1'><li id='img-%s'>%s</td><td class='report-column2'>%s</td><td class='report-column3'>%s</td></tr>" % (header.status.lower(), header.name, header.value, header.recommended)
	return table + "</tbody></table>"

def make_raw_headers_table(raw_headers):
	table = "<table class='raw-table'><thead class='table-head-up'><tr><td colspan='2'>Raw Headers</td></tr></thead><tbody>"
	for header in raw_headers:
		table += "<tr><td class='raw-column1'>%s</td><td class='raw-column2'>%s</td></tr>" % (header, raw_headers[header])
	return table + "</tbody></table>"

@app.route("/", methods=["GET"])
def index():
	report_summary_table = ""
	raw_headers_table = ""
	not_found = ""
	url = ""
	ip = ""
	URLstring = request.args.get("url")
	if URLstring:
		page_info = verifier.get_page_info(URLstring)
		if page_info != None:
			url = Markup("<p>URL: %s</p>" % page_info[0])
			ip = Markup("<p>IP Address: %s</p>" % page_info[1])
			raw_headers = page_info[2]
			security_headers = page_info[3]
			report_summary_table = Markup(make_report_summary_table(security_headers))
			raw_headers_table = Markup(make_raw_headers_table(raw_headers))

		else:
			not_found = "PAGE NOT FOUND"
	return render_template("index.html",
							url_site = url,
							ip_address = ip,
							report_summary_table = report_summary_table,
							raw_headers_table = raw_headers_table,
							not_found = not_found)

app.run(debug=True)
