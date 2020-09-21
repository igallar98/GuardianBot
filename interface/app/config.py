import os
from app import checker
class Config:
    def __init__(self):
        self.PathConfig = '../data/config.conf'
        self.chk = checker.Checker()
        self.ppslimit = 0
        self.mbitslimit = 0
        self.timecheck = 0
        self.blocktime = 0
        self.deleteRegister = 0

    def saveConfig(self):
        with open(self.PathConfig, 'w+') as file:
            file.write(str(self.ppslimit) + "|" + str(self.mbitslimit) + "|"+ str(self.timecheck) + "|" + str(self.blocktime) + "|" + str(self.deleteRegister) + "\n")

    def updateConfig(self, ppslimit, mbitslimit, timecheck, blocktime, deleteRegister):
        self.ppslimit = ppslimit
        self.mbitslimit = mbitslimit
        self.timecheck = timecheck
        self.blocktime = blocktime
        self.deleteRegister = deleteRegister

        self.saveConfig()

        self.chk.updateValue('q')


    def getConfig(self):
        if os.path.exists(self.PathConfig):
            with open(self.PathConfig, 'r') as file:
                lines = file.readlines()
                for line in lines:
                    r = line.split("|")
                    self.ppslimit = r[0]
                    self.mbitslimit = r[1]
                    self.timecheck = r[2]
                    self.blocktime = r[3]
                    self.deleteRegister = r[4]
                    return r
        else:
            return [5]*0
