#!/bin/python

from flask import Flask, request, render_template, Markup
from pyScripts.SecurityHeaders import SecurityHeaderVerifier

secure = SecurityHeaderVerifier()

app = Flask(__name__)

def format_raw_headers(self, content):
	string = ""
	for key in content:
		string = "<>%s"

@app.route("/", methods=["GET"])
def index():
	URLstring = request.args.get("url")
	print URLstring
	content = "HEADER"
	t_header = "<th>" + content + "</th>"
	t_row = "<tr>" + t_header + "</tr>"
	table = "<table id='table-one'>" + t_row + "</table>"

	info = secure.do_search(URLstring)
	if info:
		print info["ip"]
		return render_template("index.html", ip = info["ip"])
	else:
		return render_template("index.html")

app.run(debug=True)

