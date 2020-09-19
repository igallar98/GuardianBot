import requests
from scapy.all import *
import tempfile
import os
import time
from scapy.layers.http import *
from scapy.utils import hexdump

API = "http://127.0.0.1:5000/API/v1/StartTrace"

PARAMS = {'authkey':"8IVIcprqlq7SiMGwFUojgm3zoxh7Gn"}

r = requests.get(url = API, params = PARAMS)




while True:

    API = "http://127.0.0.1:5000/API/v1/getTrace"

    PARAMS = {'authkey':"8IVIcprqlq7SiMGwFUojgm3zoxh7Gn"}

    r = requests.get(url = API, params = PARAMS)



    new_file, filename = tempfile.mkstemp()
    os.write(new_file, r.content)


    try:
        for sess in sniff(offline=filename, session=TCPSession).sessions().values():
            for packet in sess:
                # Use TCPSession to automatically rebuild HTTP packets
                if HTTP in packet and Raw in packet:
                    # packet is HTTP and has payload
                    a = packet.show(dump=True)
                    if 'Apache' in a:
                        APIS = "http://127.0.0.1:5000/API/v1/postIPBlock"

                        PARAMsS = {'authkey':"8IVIcprqlq7SiMGwFUojgm3zoxh7Gn", 'ip' :packet[IP].src, 'time' : "100"}

                        r = requests.post(url = APIS, data = PARAMsS)
                        print("APACHE\n")
    except:
        continue
    time.sleep(1);
