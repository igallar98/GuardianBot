from app import app, request, render_template, url_for
from app import sharedMemory, jsonTable, blockIP, checker, blockProtocol, blockPort
from flask_session import Session

import sys
global save
save = [0]

@app.route('/')
@app.route('/index')
def index():


    return render_template('index.html', title = "Información general")



@app.route('/table.json')
@app.route('/API/v1/getStatics')
def rjsonTable():

    jTable = jsonTable.jsonTable()
    return jTable.getTable()


@app.route('/config')
def config():
    return render_template('config.html', title = "Configuración del cortafuegos")


@app.route('/shutdown', methods=['POST','GET'])
def shutdown():
    if 'shutdown' in  request.form:
        chk = checker.Checker();
        chk.updateValue('s')
        chk.shutdown_server()
    return render_template('shutdown.html', title = "Apagar el cortafuegos")



@app.route('/lock', methods=['POST','GET'])
def lock():
    return render_template('lock.html', title = "Iniciar sesión")


@app.route('/makeclean', methods=['POST','GET'])
def makeclean():
    if 'clean' in request.form:
        chk = checker.Checker();
        chk.updateValue('c')
    return "ok"

@app.route('/API/v1/postIPBlock', methods=['POST','GET'])
@app.route('/blockip', methods=['POST','GET'])
def blockip():

    if 'ip' in request.form and 'time' in request.form:
        block = blockIP.blockIP()
        block.saveIP(request.form["ip"], 0, request.form["time"])


    if 'authkey' in request.form:
        return "0"
    else:
        return render_template('blockIP.html', title = "Bloquear Dirección IP")

@app.route('/API/v1/postProtoBlock', methods=['POST','GET'])
@app.route('/blockprotocol', methods=['POST','GET'])
def blockprotocol():
    if 'time' in request.form and 'proto' in request.form:
        block = blockProtocol.BlockProtocol()
        block.blockProtocol(request.form["proto"], request.form["time"])
    if 'authkey' in request.form:
        return "0"
    else:
        return render_template('blockProtocol.html', title = "Bloquear Protocolos")

@app.route('/API/v1/postPortsBlocks', methods=['POST','GET'])
@app.route('/blockport', methods=['POST','GET'])
def blockport():
    if 'time' in request.form and 'port' in request.form:
        block = blockPort.BlockPort()
        block.blockPort(request.form["port"], request.form["time"])
    if 'authkey' in request.form:
        return "0"
    else:
        return render_template('blockPort.html', title = "Bloquear Puertos")

@app.route('/API/v1/getPortsBlocks', methods=['POST','GET'])
@app.route('/getblockport.json')
def getblockport():
    block = blockPort.BlockPort()
    return block.getTable()

@app.route('/API/v1/getProtoBlocks', methods=['POST','GET'])
@app.route('/getblockprotocol.json')
def getblockprotocol():
    block = blockProtocol.BlockProtocol()
    return block.getTable()

@app.route('/API/v1/getIPBlocks', methods=['POST','GET'])
@app.route('/getblockip.json')
def getblockip():
    block = blockIP.blockIP()
    return block.getTable()

@app.route('/API/v1/postIPUnblock', methods=['POST','GET'])
@app.route('/unblock', methods=['POST','GET'])
def unblock():
    if 'ip' in request.form:
        block = blockIP.blockIP()
        block.deleteIP(request.form["ip"], 0)
        return "0"
    return "1"
@app.route('/API/v1/postProtoUnblock', methods=['POST','GET'])
@app.route('/unblockprotocol', methods=['POST','GET'])
def unblockprotocol():
    if 'protocol' in request.form:
        block = blockProtocol.BlockProtocol()
        block.unBlockProtocol(request.form["protocol"])
        return "0"
    return "1"
@app.route('/API/v1/postPortsUnblocks', methods=['POST','GET'])
@app.route('/unblockport', methods=['POST','GET'])
def unblockport():
    if 'port' in request.form:
        block = blockPort.BlockPort()
        block.unBlockPort(request.form["port"])
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

@app.route('/API')
def api():
    return render_template('api.html', title = "API REST", url = request.url_root, key = "NULL")
