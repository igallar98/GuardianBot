import json
from app import sharedMemory
class jsonTable:

    def __init__(self):
        self.table = {};
        self.sMemory = sharedMemory.sharedMemory()
        return


    def getTable(self):
        self.table["header"] = self.header()
        self.table["data"] = self.data()
        self.table["footer"] = []
        return json.dumps(self.table)


    def header(self):
        #isIpv6 = {  "name": "isIpv6",
        #            "title": "IP",
        #            "sortable": False}
        ips = {  "name": "ips",
                    "title": "Fuente",
                    "sortable": False}
        ipd = {  "name": "ipd",
                    "title": "Destino",
                    "sortable": False}
        pkts = {  "name": "pkts",
                    "title": "Paquetes",
                    "format": "int",
                    "sortable": True,
                    "sortDir": "desc"}
        pps = {  "name": "pps",
                    "title": "Paquetes/s",
                    "format": "int",
                    "sortable": True}
        KBytes = {  "name": "KBytes",
                    "title": "KB",
                    "format": "int",
                    "sortable": True}
        Mbits = {  "name": "Mbits",
                    "title": "Mbits/s",
                    "format": "int",
                    "sortable": True,
                    "sortDir": "desc"}
        periodo = {  "name": "periodo",
                    "title": "Periodo",
                    "format": "int",
                    "sortable": True}

        #protocolo = {  "name": "protocolo",
        #            "title": "Protocolo",
        #            "sortable": True}
        return [ ips, ipd, pkts, pps, KBytes, Mbits, periodo]

    def data(self):
        table = []
        self.sMemory.refresh_table()
        sharedTable = self.sMemory.get_table()
        del sharedTable[-1]
        for row in sharedTable:
            r = row.split("|")
            aux = int(r[6]) / 1000000
            table.append([r[1], r[2], r[3], r[4], r[5], aux, r[7]])
        return table
