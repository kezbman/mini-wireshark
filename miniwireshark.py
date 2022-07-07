import re
import socket
from struct import unpack
from scapy.all import *
from binascii import unhexlify
from time import sleep

def ether(data):
    dest_mac, src_mac, proto = unpack('!6s 6s H', data[:14])
    #dest_mac = ':'.join(re.findall('..', dest_mac.encode('hex')))
    #src_mac = ':'.join(re.findall('..', src_mac.encode('hex')))

    return[dest_mac, src_mac, hex(proto), data[14:]]

def ip(data):
    maindata = data
    data = unpack('! B s H 2s 2s B B 2s 4s 4s 2s 2s 4s 4s s s', data[:34])

    # return [data[0]>>4, # version
    # (data[0]&(0x0F))*4, # header length
    # "0x"+data[1].encode('hex'), # Diffserv
    # data[2], # total length
    # "0x"+data[3].encode('hex'), # ID
    # "0x"+data[4].encode('hex'), # flags
    # data[5], # ttl
    # data[6], # protocol
    # "0x"+data[7].encode('hex'), # check sum
    # socket.inet_ntoa(data[8]),  # src ip
    # socket.inet_ntoa(data[9]),  # dest ip
    # maindata[(data[0]&(0x0F))*4:] #ip payload
    # ]
    
    if ((data[14][0]%16) == 0):
        if (str(hex(data[15][0])).replace('0x','') == "12"):
            flg = str(hex(data[14][0])).replace('0x','')  + str(hex(data[15][0])).replace('0x','')
        elif (str(hex(data[15][0])).replace('0x','') == "2"):
            flg = str(hex(data[14][0])).replace('0x','')  + '0' + str(hex(data[15][0])).replace('0x','')
        else:
            flg = "0000"
    else:
        flg = "0000"

    return {
    'src_ip':  socket.inet_ntoa(data[8]),  
    'dest_ip': socket.inet_ntoa(data[9]),  
    'src_port':  data[10][0]*256+data[10][1],  
    'dest_port': data[11][0]*256+data[11][1],  
    'Flags': flg
    }


iface_name = "Wi-Fi"
iface = IFACES.dev_from_name(iface_name) 
sock = conf.L2listen(iface=iface)

SYN = "002"
SYN_ACK = "012"

while True:
    raw_data = sock.recv_raw(1000)[1]
    #raw_data = sock.recv()
    if raw_data != None:
        ether_shark = ether(raw_data)
        if (ether_shark[2] == '0x800'):
            ip_shark=ip(ether_shark[3])
            if (ip_shark['Flags'][1:] == SYN_ACK ): # and ip_shark['src_port'] != 443
                print('port {} is open on {}'.format(ip_shark['src_port'], ip_shark['src_ip']))
                #print(ip_shark)
                #print('\n')
            # elif (ip_shark['Flags'][1:] == SYN):
            #     print('A SYN packet:')
            #     print(ip_shark)
            #     print('\n')
               
            
    
 


