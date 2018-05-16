#!/bin/python

from flask import Flask, request, render_template

app = Flask(__name__)

@app.route("/", methods=["GET"])
def index():
	URLstring = request.args.get("url")
	print URLstring
	return render_template("index.html")

app.run(debug=True)
