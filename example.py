import requests
from scapy.all import *
import tempfile
import os
import time
from scapy.layers.http import *
from scapy.utils import hexdump
import tkinter
from tkinter import messagebox



API = "http://127.0.0.1:4020/API/v1/StartTrace"

PARAMS = {'authkey':"8IVIcprqlq7SiMGwFUojgm3zoxh7Gn"}

r = requests.get(url = API, params = PARAMS)

f, filename = tempfile.mkstemp()

lh = 0

root = tkinter.Tk()
root.withdraw()
rootnum = 0

while True:


    API = "http://127.0.0.1:4020/API/v1/getTrace"

    PARAMS = {'authkey':"8IVIcprqlq7SiMGwFUojgm3zoxh7Gn"}

    with requests.get(url = API, params = PARAMS, stream=True) as r:
        os.truncate(f, lh)
        os.lseek(f, 0, 0)
        os.write(f, r.content)
        lh = len(r.content)

    try:
        pcap = rdpcap(filename)
    except:
        continue


    for packet in pcap:
        # packet is HTTP and has payload
        a = packet.show(dump=True)
        #packet.show()
        if 'STANDARD' in a and packet.haslayer(IP):
            #packet.show()
            API = "http://127.0.0.1:4020/API/v1/postIPBlock"
            PARAMS = {'authkey':"8IVIcprqlq7SiMGwFUojgm3zoxh7Gn", 'ip' :packet[IP].src, 'time' : "100"}

            with requests.post(url = API, data = PARAMS) as r:
                if rootnum == 0:
                    messagebox.showinfo("¡Alerta!", "Huella detectada")
                    root.update()
                    rootnum = 1


    time.sleep(1)






f.close()
