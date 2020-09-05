import sysv_ipc as ipc


KEY = 8888



class sharedMemory:



    def __init__(self):
        self.table = [];

        return

    def refresh_table(self):
        try:
            shm = ipc.SharedMemory(KEY, 0, 0)

            shm.attach(0,0)
            buf = shm.read()

            shm.detach()

            return buf
        except:
            return 0
