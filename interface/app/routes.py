from app import app, request, render_template, url_for



@app.route('/')
@app.route('/index')
def index():
    url_for('static', filename='path/to/file')

    return render_template('index.html', title = "Información general")
