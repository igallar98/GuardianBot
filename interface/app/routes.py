from app import app, request, render_template, url_for
from app import sharedMemory, jsonTable, blockIP

global save
save = [0]

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

@app.route('/blockip', methods=['POST','GET'])
def blockip():
    if 'ip' in request.form and 'prefix' in request.form and 'time' in request.form:
        block = blockIP.blockIP()
        block.saveIP(request.form["ip"], request.form["prefix"], request.form["time"])

    return render_template('blockIP.html', title = "Bloquear Dirección IP")

@app.route('/getblockip.json')
def getblockip():
    block = blockIP.blockIP()
    return block.getTable()

@app.route('/unblock', methods=['POST','GET'])
def unblock():
    if 'ip' in request.form and 'prefix' in request.form:
        block = blockIP.blockIP()
        block.deleteIP(request.form["ip"], request.form["prefix"])
        return "0"
    return "1"

@app.route('/getipinfo', methods=['POST','GET'])
def getipinfo():
    global save
    if 'sip' in request.args and 'dip' in request.args:
        sMemory = sharedMemory.sharedMemory();
        infot = sMemory.getRecord(request.args["sip"], request.args["dip"])
        proto = sMemory.parseProtocolo(infot[10])
        if save[0] == request.args["sip"] + request.args["sip"]:
            tupla = (proto, infot[8], infot[9])
            if tupla not in save:
                save.append(tupla)
        else:
            save = []
            save.append(request.args["sip"] + request.args["sip"])

        return render_template('getipinfo.html', sip = request.args["sip"],
                dip = request.args["dip"], info = infot, proto = proto, save = save)
