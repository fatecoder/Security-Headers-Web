#!/bin/python

from flask import Flask, request, render_template, Markup
from pyScripts.SecurityHeaders import Verifier
secure = Verifier()

app = Flask(__name__)

def get_content(string):
	url = secure.replace_scheme(string,"https")
	content = secure.get_all_info(url)
	if content:
		return secure.get_all_info(url)
	else:
		url = secure.replace_scheme(string,"http")
		content = secure.get_all_info(url)
		if content:
			return secure.get_all_info(url)
		else:
			return False

def make_table(dictionary):
	table = "<table class='raw-table'><thead class='table-head'><tr><td colspan='2'>RAW HEADERS</td></tr></thead><tbody>"
	for key in dictionary:
		table += "<tr><td class='column1'>%s</td><td class='column2'>%s</td></tr>" % (key, dictionary[key])
	return table + "</tbody></table>"

@app.route("/", methods=["GET"])
def index():
	URLstring = request.args.get("url")
	if URLstring:
		c = get_content(URLstring)
		if c:
			return render_template("index.html", table = Markup(make_table(c[2])))
		else:
			return render_template("index.html", ip = "PAGE NOT FOUND")
	else:
		return render_template("index.html")

app.run(debug=True)

