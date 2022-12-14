import messages_pb2
from scapy.all import sniff
import json
import socket
import asyncio
from pywizlight import discovery
import configparser
import threading
import  signal
from datetime import datetime, time, timedelta
import time
 #here is some how is this possible blame me somehow
SNIFF_INTERVAL = 0.5
led_ip = []
power_buff = 6 * [0]
class ProgramKilled(Exception):
    pass

def signal_handler(signum, frame):
    raise ProgramKilled

class Job(threading.Thread):
    def __init__(self, interval, execute, *args, **kwargs):
        threading.Thread.__init__(self)
        self.daemon = False
        self.stopped = threading.Event()
        self.interval = interval
        self.execute = execute
        self.args = args
        self.kwargs = kwargs
        
    def stop(self):
                self.stopped.set()
                self.join()
    def run(self):
            while not self.stopped.wait(self.interval.total_seconds()):
                self.execute(*self.args, **self.kwargs)

config = configparser.ConfigParser()

config.read('config.ini')
message = messages_pb2.ClientToServer()

power_mode = dict(config.items('MODE'))
power_mode = power_mode['power_mode']

second_ip = dict(config.items('IP'))
second_ip = second_ip['led_ip']

cfg = {s:dict(config.items(s)) for s in config.sections()[2:]}



def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP


def send_data_udp(params, led_ip):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        data = {"method":"setPilot","params":params}
        sock.connect((led_ip, 38899))
        sock.send(bytes(json.dumps(data), encoding='utf-8'))
        resp = sock.recv(2048)
        

def light_manipulation(params):  
    threads = []
    for i in range(len(led_ip)):   
        t = threading.Thread(target=send_data_udp, args=(params, led_ip[i]))
        t.daemon = False
        threads.append(t)
    for j in range(len(led_ip)):
        threads[j].start()
    for k in range(len(led_ip)):
        threads[k].join()


def bulb_handler(power):
    for zone in cfg:
        power_from = int(cfg[zone]["power_from"])
        power_to = int(cfg[zone]["power_to"])
        dimming = int(cfg[zone]["dimming"])
        if power >= power_from and power < power_to:
            r = int(cfg[zone]["r"])
            g = int(cfg[zone]["g"])
            b = int(cfg[zone]["b"])
            light_manipulation({"r":r,"g":g,"b":b,"dimming":dimming})
            break
def handler(packet):
    global timson
    timson = datetime.now()
    data = packet.load.hex()
    offset = int(data[0:2], 16)
    data = data[2*(offset-1):-8]
    data = bytearray.fromhex(data)
    message.ParseFromString(data)
    power = message.state.power
    bulb_handler(power)
    

def handler_avg(packet):
    data = packet.load.hex()
    offset = int(data[0:2], 16)
    data = data[2*(offset-1):-8]
    data = bytearray.fromhex(data)
    message.ParseFromString(data)
    power_buff.pop(0)
    power = message.state.power
    power_buff.append(power)
    power = int(sum(power_buff)/6)
    bulb_handler(power)


async def find_bulb():
    ip_area = get_ip().split('.')
    ip_area.pop()
    ip_area.append('255')
    ip_area = '.'.join(ip_area)
    bulbs = await discovery.discover_lights(broadcast_space=f"{ip_area}")
    a = []
    for bulb in bulbs:
        a.append((bulb.__dict__["ip"]))
    return a
    
delta = 0

def sniff_handler():
    sniff(filter=f"dst port 3022", prn=handler if power_mode == 'now' else handler_avg, count=1)


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    loop = asyncio.get_event_loop()
    sniff_job = Job(interval=timedelta(seconds=SNIFF_INTERVAL), execute=sniff_handler)
    sniff_job.start()
    print("Searching for WIZ bulbs...")
    led_ip = loop.run_until_complete(find_bulb())
    if not led_ip:
        led_ip = [second_ip]
        print("No bulbs found... Using config ip")
    else:
        print(f"Found {len(led_ip)} bulbs...")
        print(f"Running App...")
    while True:
        try:
            if not led_ip:
                break
            a = []
            
        except ProgramKilled:
            sniff_job.stop()
            print("Pogram killed, doing cleaning things...")
            break


    


