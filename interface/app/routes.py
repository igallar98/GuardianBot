from app import app, request, render_template, url_for

import sysv_ipc as ipc

def xd():
    shm = ipc.SharedMemory(18234, 0, 0)

    #I found if we do not attach ourselves
    #it will attach as ReadOnly.
    shm.attach(0,0)
    buf = shm.read()

    print(buf.decode("utf-8") )
    shm.detach()
    pass

@app.route('/')
@app.route('/index')
def index():
    url_for('static', filename='path/to/file')
    xd()
    return render_template('index.html', title = "Información general")
