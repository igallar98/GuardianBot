from app import app, request, render_template, url_for
from app import sharedMemory, jsonTable


@app.route('/')
@app.route('/index')
def index():


    return render_template('index.html', title = "Información general")



@app.route('/table.json')
def rjsonTable():
    jTable = jsonTable.jsonTable()
    return jTable.getTable()


@app.route('/config')
def config():
    return render_template('config.html', title = "Configuración del cortafuegos")


@app.route('/lock')
def lock():
    return render_template('lock.html', title = "Iniciar sesión")
