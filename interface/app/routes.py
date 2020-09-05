from app import app, request, render_template, url_for
from app import sharedMemory


@app.route('/')
@app.route('/index')
def index():
    url_for('static', filename='path/to/file')
    xd()
    return render_template('index.html', title = "Información general")
