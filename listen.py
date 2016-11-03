import socket as sck
import struct
import binascii
import ctypes
import sys

import code

def main():

    HOST = 'localhost'
    PORT = 8001


    device='eth1'

    addr = (HOST,PORT)
    sock = sck.socket(sck.AF_PACKET,sck.SOCK_RAW,sck.IPPROTO_RAW)
    #sock = sck.socket(sck.AF_INET,sck.SOCK_RAW,sck.IPPROTO_UDP)

    iface=(device,0x0800)

    # Include IP headers
    #sock.setsockopt(sck.IPPROTO_IP, sck.IP_HDRINCL, 1)

    # receive all packages
    #sock.ioctl(sck.SIO_RCVALL, sck.RCVALL_ON)


    sock.bind(iface)

    #sock.bind(addr)

    

    print "Listening to: " ,iface

    while True:
        raw_buffer = sock.recv(65535)
        

        #print "received: ", raw_buffer

        eth_header = raw_buffer[0:14]
        ip_header = raw_buffer[14:34]
        udp_header= raw_buffer[34:42]
        

        
        ethh = struct.unpack('!6s6s2s' , eth_header)
        #print ethh

        #print "raw header: " ,ip_header
        iph = struct.unpack('!1s1s1H1H2s1B1B2s4s4s' , ip_header)
        #print iph


        udph=struct.unpack('!HHHH', udp_header)
        #print udph



        #Extract DL Info
        srcMac = binascii.hexlify(ethh[1])
        dstMac = binascii.hexlify(ethh[0])
        ethType = binascii.hexlify(ethh[2])


    

        #Extract NW Info
        
        ver_head_length = iph[0]
        service_field = binascii.hexlify(iph[1])
        total_length = str(iph[2])
        identification = str(iph[3])
        flag_frag = binascii.hexlify(iph[4])
        ttl = str(iph[5])
        protocol = str(iph[6])
        checkSum = binascii.hexlify(iph[7])
        src_ip = sck.inet_ntoa(iph[8])
        dst_ip = sck.inet_ntoa(iph[9])
         


        b = bytearray()
        b.extend(iph[0])

        verl=int(b[0])
        ver = (verl >> 4) & 0xf
        h_len = verl & 0xf


        #Extract TP Info

        srcPort=udph[0]
        dstPort=udph[1]
        dataLenght=udph[2]
        tp_checksum=udph[3]
        

        #Extract Data

        data=raw_buffer[42:42+dataLenght]

        #Extract DL Trailer

        eth_trailer=raw_buffer[42+dataLenght:]


        if protocol=='17' and dstPort==8001:
            print "##########################################################"
            print "Dati ricevuti: ",len(raw_buffer)
            ip_str=struct.unpack('!HHHHHHHHHH' , ip_header)
            print "##########################################################"
            for s in ip_str:
                print ("%0.4X" % s)
            print "##########################################################"


if __name__=='__main__':
    main()




''' 
    UDP Header HEX

eb 0e 1f 41 00 0d fe 20

    From Wireshark
'''

'''
ALL PACKET
0000   00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00
0010   00 21 2e 11 40 00 40 11 0e b9 7f 00 00 01 7f 00
0020   00 01 eb 0e 1f 41 00 0d fe 20 63 69 61 6f 0a

'''


'''
    IP PSEUDO HEADER

    ip sorgente
    ip destinazione
    reserved 8bit zeri
    protocollo da ip 
    lunghezza udp 
'''