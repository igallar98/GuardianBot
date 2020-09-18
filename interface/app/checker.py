import sysv_ipc as ipc
from flask import request



class Checker:
    def __init__(self):
        self.table = [];
        return

    def updateValue(self, character):
        shm = ipc.SharedMemory(2244, 0, 0)
        #Write and read
        shm.attach(0,100000)

        shm.write(character)

        shm.detach()


    def sendValue(self, data):
        shm = ipc.SharedMemory(2248, 0, 0)
        #Write and read
        shm.attach(0,100000)

        shm.write(data)

        shm.detach()


    def shutdown_server(self):
        func = request.environ.get('werkzeug.server.shutdown')
        if func is None:
            raise RuntimeError('Not running with the Werkzeug Server')
        func()
