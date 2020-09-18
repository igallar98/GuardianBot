import sysv_ipc as ipc
import json
import time
from app import checker

KEY = 8888



class blockIP:
    def __init__(self):
        self.ipBlockedPath = '../data/ipBlocked.data'
        self.table = {};
        self.chk = checker.Checker()

    def saveIP(self, ip, prefix, blockTime):
        self.deleteIP(ip, prefix, False)


        isV6 = 0
        if ":" in ip:
            isV6 = 1
        with open(self.ipBlockedPath, 'a') as file:
            if int(blockTime) != -1:
                file.write(str(isV6) + "|" + ip + "|" + str(prefix) + "|" + str(int(blockTime) + int(time.time())) + "\n")
            else:
                file.write(str(isV6) + "|" + ip + "|" + str(prefix) + "|" + "-1" + "\n")
        self.chk.updateValue('b')
        if int(blockTime) == -1:
            self.chk.sendValue(str(isV6) + "|" + ip + "|" + str(prefix) + "|" + "-1" + "\n")
        else:
            self.chk.sendValue(str(isV6) + "|" + ip + "|" + str(prefix) + "|" + str(int(blockTime) + int(time.time())) + "\n")



    def deleteIP(self, ip, prefix, upd = True):
        isV6 = 0
        if ":" in ip:
            isV6 = 1
        with open(self.ipBlockedPath, 'r') as f:
            lines = f.readlines()
        with open(self.ipBlockedPath, 'w') as f:
            for line in lines:
                r = line.split("|")
                if not (r[1] == ip):
                    f.write(line)
        if upd:
            self.chk.updateValue('u')
            self.chk.sendValue(str(isV6) + "|" + ip + "\n")




    def getDataBlocked(self):
        datatable = []
        with open(self.ipBlockedPath, 'r+') as file:
            lines = file.readlines()
            for row in lines:
                r = row.split("|")
                if int(r[3]) == -1:
                    datatable.append([r[1], '<center>Permanente</center>'])
                else:
                    datatable.append([r[1], '<div data-role="countdown" data-seconds="' + str(int(r[3]) - int(time.time())) + '"></div>'])
        return datatable


    def headerTable(self):
        ip = {  "name": "ip",
                    "title": "Dirección",
                    "sortable": False}

        time = {  "name": "time",
                    "title": "Tiempo",
                    "sortable": False}


        return [ip, time]

    def getTable(self):
        self.table["header"] = self.headerTable()
        self.table["data"] = self.getDataBlocked()
        self.table["footer"] = []
        return json.dumps(self.table)
