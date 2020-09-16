import sysv_ipc as ipc
import json
import time
from app import checker

KEY = 8888



class BlockPort:

    def __init__(self):
        self.ipBlockedPath = '../data/portBlocked.data'
        self.table = {};
        self.chk = checker.Checker()


    def blockPort(self, port, blockTime):
        with open(self.ipBlockedPath, 'a') as file:
            if int(blockTime) != -1:
                file.write(str(port) + "|" + str(int(blockTime) + int(time.time())) + "\n")
            else:
                file.write(str(port) + "|" + "-1" + "\n")
        self.chk.updateValue('0')
        if int(blockTime) != -1:
            self.chk.sendValue(str(port) + "|" + str(int(blockTime) + int(time.time())) + "\n")
        else:
            self.chk.sendValue(str(port) + "|" + "-1" + "\n")

    def unBlockPort(self, port):
        with open(self.ipBlockedPath, 'r') as f:
            lines = f.readlines()
        with open(self.ipBlockedPath, 'w') as f:
            for line in lines:
                r = line.split("|")
                if not (r[0] == port):
                    f.write(line)

        self.chk.updateValue('1')
        self.chk.sendValue(port)


    def getDataBlocked(self):
        datatable = []
        with open(self.ipBlockedPath, 'r+') as file:
            lines = file.readlines()
            for row in lines:
                r = row.split("|")
                if int(r[1]) == -1:
                    datatable.append([r[0], '<center>Permanente</center>'])
                else:
                    datatable.append([r[0], '<div data-role="countdown" data-seconds="' + str(int(r[1]) - int(time.time())) + '"></div>'])
        return datatable



    def headerTable(self):
        ip = {  "name": "port",
                    "title": "Puerto",
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
