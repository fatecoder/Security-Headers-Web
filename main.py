#!/bin/python

from flask import Flask, request, render_template

app = Flask(__name__)

@app.route("/")
def index():
	print "hello world"
	return render_template("index.html")

app.run(debug=True)
