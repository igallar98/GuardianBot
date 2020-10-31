from flask import Flask, request, render_template, url_for, session, redirect, send_file
from gevent.pywsgi import WSGIServer
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
app.config['SESSION_TYPE'] = 'filesystem'

from app import routes, request, render_template, url_for

http_server = WSGIServer(('', 4020), app)
http_server.serve_forever()
#app.run(debug=True)
