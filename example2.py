# nmap -v scanme.nmap.org


import argparse , sys, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import datetime
import socket
from decimal import Decimal
import tempfile
import os
import requests
import tkinter
from tkinter import messagebox



def end(fl):
    API = "http://127.0.0.1:4020/API/v1/StopTrace"

    PARAMS = {'authkey':"vzkTx3652MKsLNmV4wH3oaGSzsfMGP"}

    r = requests.get(url = API, params = PARAMS)
    os.close(fl)
    exit()

pkts = {}

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80


API = "http://127.0.0.1:4020/API/v1/StartTrace"

PARAMS = {'authkey':"vzkTx3652MKsLNmV4wH3oaGSzsfMGP"}

r = requests.get(url = API, params = PARAMS)


lhf = 0

root = tkinter.Tk()
root.withdraw()
rootnum = 0


fl, filename = tempfile.mkstemp()

while True:

    flujosdict = {}
    count = 0
    lenght = 0
    old_time = 0

    flag_urg =0
    flag_ack =0
    flag_psh =0
    flag_rst =0
    flag_syn =0
    flag_fin =0

    API = "http://127.0.0.1:4020/API/v1/getTrace"

    PARAMS = {'authkey':"vzkTx3652MKsLNmV4wH3oaGSzsfMGP"}

    with requests.get(url = API, params = PARAMS, stream=True) as r:
        os.truncate(fl, lhf)
        os.lseek(fl, 0, 0)
        os.write(fl, r.content)
        lhf = len(r.content)

    try:
        pkts = rdpcap(filename)
    except:
        continue

    for pkt in pkts:
        if pkt.haslayer(IP):
            if pkt.haslayer(TCP):
                F = pkt[TCP].flags    # this should give you an integer

                if F & URG:
                    flag_urg=1
                # FIN flag activated
                if F & ACK:
                    flag_ack=1
                # SYN flag activated
                # rest of the flags here
                if F & PSH:
                    flag_psh=1

                if F & RST:
                    flag_rst=1

                if F & SYN:
                    flag_syn=1

                if F & FIN:
                    flag_fin=1


                if flag_rst > 0:
                    auxset =(pkt[IP].src, pkt[IP].dst , pkt[TCP].sport, pkt[TCP].dport)


                    if auxset in flujosdict:
                        flujosdict[auxset]+=1
                    else:
                        flujosdict[auxset] = 0


    for key,value in flujosdict.items():
        if value <= 4:
            API = "http://127.0.0.1:4020/API/v1/postIPBlock"
            PARAMS = {'authkey':"vzkTx3652MKsLNmV4wH3oaGSzsfMGP", 'ip' :key[0], 'time' : "100"}

            with requests.post(url = API, data = PARAMS) as r:
                messagebox.showinfo("¡Alerta!", "Escaneo con NMAP detectado a la IP: " + key[0] + " desde la IP: " + key[1])
                root.update()
                end(fl)

os.close(fl)
