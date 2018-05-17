#!/bin/python

from flask import Flask, request, render_template, Markup
from pyScripts.SecurityHeadersConsole import SecurityHeaderVerifier

secure = SecurityHeaderVerifier()

app = Flask(__name__)

@app.route("/", methods=["GET"])
def index():
	URLstring = request.args.get("url")
	print URLstring
	content = "HEADER"
	t_header = "<th>" + content + "</th>"
	t_row = "<tr>" + t_header + "</tr>"
	table = "<table id='table-one'>" + t_row + "</table>";
	if URLstring == "asd":
		table = Markup(table)

		secure.do_search(URLstring)
		return render_template("index.html", table = table)
	else:
		return render_template("index.html")

app.run(debug=True)
