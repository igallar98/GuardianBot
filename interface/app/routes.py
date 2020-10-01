from app import app, request, render_template, url_for, redirect, send_file
from app import sharedMemory, jsonTable, blockIP
from app import checker, blockProtocol, blockPort, auth, config
import sys, os, io


global save
save = [0]

@app.route('/')
@app.route('/index')
def index():
    ath =  auth.Auth()
    if not ath.checkSession():
            return redirect(url_for('lock'))
    return render_template('index.html', title = "Información general")

@app.route('/exit')
def exit():
    ath =  auth.Auth().exit()
    return redirect(url_for('lock'))

@app.route('/API/v1/StartTrace', methods=['POST','GET'])
def StartTrace():
    ath =  auth.Auth()
    if not ath.checkSession():
        if 'authkey' in  request.args:
            if not ath.checkKey(request.args["authkey"]):
                return "-1"
        else:
            return redirect(url_for('lock'))

    chk = checker.Checker();
    chk.updateValue('e')
    return "0"

@app.route('/API/v1/StopTrace', methods=['POST','GET'])
def StopTrace():
    ath =  auth.Auth()
    if not ath.checkSession():
        if 'authkey' in  request.args:
            if not ath.checkKey(request.args["authkey"]):
                return "-1"
        else:
            return redirect(url_for('lock'))

    chk = checker.Checker();
    chk.updateValue('8')
    return "0"

@app.route('/API/v1/getTrace', methods=['POST','GET'])
def getTrace():
    ath =  auth.Auth()
    if not ath.checkSession():
        if 'authkey' in  request.args:
            if not ath.checkKey(request.args["authkey"]):
                return "-1"
        else:
            return redirect(url_for('lock'))
    if os.path.exists("../data/guardian.pcap"):
        with open("../data/guardian.pcap" , 'rb') as file:
            return send_file(
                     io.BytesIO(file.read()),
                     attachment_filename='guardian.pcap',
                     mimetype='text/plain'
               )
    return "1"


@app.route('/table.json')
@app.route('/API/v1/getStatics', methods=['POST','GET'])
def rjsonTable():
    ath =  auth.Auth()
    if not ath.checkSession():
        if 'authkey' in  request.args:
            if not ath.checkKey(request.args["authkey"]):
                return "-1"
        else:
            return redirect(url_for('lock'))
    jTable = jsonTable.jsonTable()
    return jTable.getTable()

@app.route('/config', methods=['POST','GET'])
def configServer():
    cnf = config.Config()
    if 'timecheck' in  request.form:
        cnf.updateConfig(request.form["ppslimit"], request.form["mbitslimit"], request.form["timecheck"], request.form["blocktime"], request.form["deleteRegister"])

    ath =  auth.Auth()
    if not ath.checkSession():
            return redirect(url_for('lock'))
    return render_template('config.html', title = "Configuración del cortafuegos",config =  cnf.getConfig())


@app.route('/shutdown', methods=['POST','GET'])
def shutdown():
    ath =  auth.Auth()
    if not ath.checkSession():
        if 'authkey' in  request.form:
            if not ath.checkKey(request.form["authkey"]):
                return "-1"
        else:
            return redirect(url_for('lock'))
    if 'shutdown' in  request.form:
        chk = checker.Checker();
        chk.updateValue('s')
        chk.shutdown_server()
    return render_template('shutdown.html', title = "Apagar el cortafuegos")



@app.route('/lock', methods=['POST','GET'])
def lock():

    if 'password' in request.form:
        if auth.Auth().checkPassword(request.form["password"]):
            return redirect(url_for('index'))
    else:
        return render_template('lock.html', title = "Iniciar sesión", error = True)
    return render_template('lock.html', title = "Iniciar sesión", error = False)


@app.route('/API/v1/makeClean', methods=['POST','GET'])
@app.route('/makeclean', methods=['POST','GET'])
def makeclean():
    ath =  auth.Auth()
    if not ath.checkSession():
        if 'authkey' in  request.form:
            if not ath.checkKey(request.form["authkey"]):
                return "-1"
        else:
            return redirect(url_for('lock'))
    if 'clean' in request.form or 'authkey' in request.form:
        chk = checker.Checker();
        chk.updateValue('c')
        return "0"
    return "-1"

@app.route('/API/v1/postIPBlock', methods=['POST','GET'])
@app.route('/blockip', methods=['POST','GET'])
def blockip():
    ath =  auth.Auth()
    if not ath.checkSession():
        if 'authkey' in  request.form:
            if not ath.checkKey(request.form["authkey"]):
                return "-1"
        else:
            return redirect(url_for('lock'))
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
    ath =  auth.Auth()
    if not ath.checkSession():
        if 'authkey' in  request.form:
            if not ath.checkKey(request.form["authkey"]):
                return "-1"
        else:
            return redirect(url_for('lock'))

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
    ath =  auth.Auth()
    if not ath.checkSession():
        if 'authkey' in  request.form:
            if not ath.checkKey(request.form["authkey"]):
                return "-1"
        else:
            return redirect(url_for('lock'))

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
    ath =  auth.Auth()
    if not ath.checkSession():
        if 'authkey' in  request.args:
            if not ath.checkKey(request.args["authkey"]):
                return "-1"
        else:
            return redirect(url_for('lock'))

    block = blockPort.BlockPort()
    return block.getTable()

@app.route('/API/v1/getProtoBlocks', methods=['POST','GET'])
@app.route('/getblockprotocol.json')
def getblockprotocol():
    ath =  auth.Auth()
    if not ath.checkSession():
        if 'authkey' in  request.args:
            if not ath.checkKey(request.args["authkey"]):
                return "-1"
        else:
            return redirect(url_for('lock'))

    block = blockProtocol.BlockProtocol()
    return block.getTable()

@app.route('/API/v1/getIPBlocks', methods=['POST','GET'])
@app.route('/getblockip.json')
def getblockip():
    ath =  auth.Auth()
    if not ath.checkSession():
        if 'authkey' in  request.args:
            if not ath.checkKey(request.args["authkey"]):
                return "-1"
        else:
            return redirect(url_for('lock'))

    block = blockIP.blockIP()
    return block.getTable()

@app.route('/API/v1/postIPUnblock', methods=['POST','GET'])
@app.route('/unblock', methods=['POST','GET'])
def unblock():
    ath =  auth.Auth()
    if not ath.checkSession():
        if 'authkey' in  request.form:
            if not ath.checkKey(request.form["authkey"]):
                return "-1"
        else:
            return redirect(url_for('lock'))

    if 'ip' in request.form:
        block = blockIP.blockIP()
        block.deleteIP(request.form["ip"], 0)
        return "0"
    return "1"
@app.route('/API/v1/postProtoUnblock', methods=['POST','GET'])
@app.route('/unblockprotocol', methods=['POST','GET'])
def unblockprotocol():
    ath =  auth.Auth()
    if not ath.checkSession():
        if 'authkey' in  request.form:
            if not ath.checkKey(request.form["authkey"]):
                return "-1"
        else:
            return redirect(url_for('lock'))

    if 'protocol' in request.form:
        block = blockProtocol.BlockProtocol()
        block.unBlockProtocol(request.form["protocol"])
        return "0"
    return "1"
@app.route('/API/v1/postPortsUnblocks', methods=['POST','GET'])
@app.route('/unblockport', methods=['POST','GET'])
def unblockport():
    ath =  auth.Auth()
    if not ath.checkSession():
        if 'authkey' in  request.form:
            if not ath.checkKey(request.form["authkey"]):
                return "-1"
        else:
            return redirect(url_for('lock'))
    if 'port' in request.form:
        block = blockPort.BlockPort()
        block.unBlockPort(request.form["port"])
        return "0"
    return "1"

@app.route('/getipinfo', methods=['POST','GET'])
def getipinfo():
    ath =  auth.Auth()
    if not ath.checkSession():
        return redirect(url_for('lock'))
    global save
    if 'sip' in request.args and 'dip' in request.args:
        sMemory = sharedMemory.sharedMemory();
        infot = sMemory.getRecord(request.args["sip"], request.args["dip"])
        while infot == -1:
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

@app.route('/API', methods=['POST','GET'])
def api():
    ath =  auth.Auth()
    if not ath.checkSession():
        return redirect(url_for('lock'))
    if 'key' in request.args:
        ath.generateKey()

    return render_template('api.html', title = "API REST", url = request.url_root, key = ath.getKey())
