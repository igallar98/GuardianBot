from flask import Flask, request, render_template, url_for


app = Flask(__name__)

from app import routes, request, render_template, url_for


app.run(debug=True)
