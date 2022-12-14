from scapy.all import sniff

#added comment to solve confgregre gerg ergergreger
while True:
        a = []
        sniff(filter=f"dst port 3022", prn= lambda x: print(x))
