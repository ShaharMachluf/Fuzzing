from scapy.all import *

def show(pkt):
    try:
        data = pkt[Raw].load.decode()
    except Exception:
        return;
    if len(data)>= 100:  # ssh payload shouldn't be so long
        print("fuzzing detected")
        exit(0)
    elif data[-1]!= '\n' or data[-2]!='\r':  # ssh payload should always end with this two chars
        print("fuzzing detected")
        exit(0)
    elif "://" in data:  # not related to ssh protocol
        print("fuzzing detected")
        exit(0)
    for i in range(3, len(data)):
        if data[i-3] == data[i-2] == data[i-1] == data[i]: # a long seq of the same char
            print("fuzzing detected")
            exit(0)
    version = data.split('-')
    if version[0] == "SSH" and version[1]!="2.0":  # invlid version
        print("fuzzing detected")
        exit(0)


interface = input("please enter the interface you want to sniff\n")
pkt = sniff(iface=interface, filter="tcp port 22", prn=show)