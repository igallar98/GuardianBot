from flask import Flask, request, render_template, url_for, session, redirect, send_file
from gevent.pywsgi import WSGIServer


app = Flask(__name__)
app.secret_key = "8IVIcprqlq7SiMGwFUojgm3zoxh7Gn"
app.config['SESSION_TYPE'] = 'filesystem'

from app import routes, request, render_template, url_for

http_server = WSGIServer(('', 5000), app)
http_server.serve_forever()
#app.run(debug=True)
