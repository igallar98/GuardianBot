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
