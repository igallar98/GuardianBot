from flask import Flask, request, render_template, url_for, session, redirect


app = Flask(__name__)
app.secret_key = "8IVIcprqlq7SiMGwFUojgm3zoxh7Gn"
app.config['SESSION_TYPE'] = 'filesystem'

from app import routes, request, render_template, url_for


app.run(debug=True)
