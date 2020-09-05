from app import app, request, render_template, url_for
from app import sharedMemory, jsonTable


@app.route('/')
@app.route('/index')
def index():
    url_for('static', filename='path/to/file')
    sMemory = sharedMemory.sharedMemory()
    sMemory.refresh_table()
    for row in sMemory.get_table():
        table = row.split("|")
        print(table[0])


    return render_template('index.html', title = "Información general")



@app.route('/table.json')
def rjsonTable():
    jTable = jsonTable.jsonTable()
    return jTable.getTable()
