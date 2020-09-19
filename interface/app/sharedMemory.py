import sysv_ipc as ipc


KEY = 8888


class sharedMemory:
    def __init__(self):
        self.table = [];
        return

    def __refresh_table(self):
        try:
            shm = ipc.SharedMemory(KEY, 0, 0)

            shm.attach(0,0)
            buf = shm.read()

            shm.detach()

            self.table = buf.decode("utf-8").split("\n")

            return 1
        except ipc.ExistentialError:
            return -1



    def refresh_table(self):
        while self.__refresh_table() == -1:
            pass

    def get_table(self):
        return self.table

    def parseProtocolo(self, proto):
        if proto == 'u':
            return "UDP"
        elif proto == 't':
            return "TCP"
        elif proto == 'i':
            return "ICMP"
        elif proto == '6':
            return "IPV6"
        elif proto == 'p':
            return "IP"
        return "?"


    def getRecord(self, ips, ipa):
        self.refresh_table()
        sharedTable = self.get_table()
        del sharedTable[-1]
        for row in sharedTable:
            r = row.split("|")
            if r[1] == ips and r[2] == ipa:
                return r
        return -1
