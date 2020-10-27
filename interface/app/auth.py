import string
import random
import os
from flask_session import Session
from flask import session
import crypt, getpass

class Auth:
    def __init__(self):
        self.PathKey = '../data/key.data'
        self.PathmKey = '../data/mkey.data'
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

    def checkKey(self, key):
        self.getKey()
        return (key== self.key)


    def exit(self):
        self.getKey()
        session['logged'] = False


    def checkPassword(self, password):
        with open(self.PathmKey) as file:
            if crypt.crypt(password, "gbot").strip() == file.readline().strip():
                session['logged'] = True
            return session.get('logged', False)


    def checkSession(self):
        return session.get('logged', False)
