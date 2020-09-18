import string
import random
import os
from flask_session import Session


class Auth:
    def __init__(self):
        self.PathKey = '../data/key.data'
        self.key = "NULL";

    def random_string(self, length):
        return ''.join(random.choice(string.ascii_letters + string.digits) for m in range(length))

    def generateKey(self):
        with open(self.PathKey , 'w+') as file:
            s = self.random_string(30)
            file.write(s)
            self.key = s

    def getKey(self):
        if os.path.exists(self.PathKey):
            with open(self.PathKey , 'r') as file:
                self.key = file.read()
        else:
            self.generateKey()

        return self.key
