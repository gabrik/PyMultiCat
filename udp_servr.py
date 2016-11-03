import socket as sck
import struct
import binascii
import ctypes
from utils import inet_utils
import sys

import code

def main():





	if len(sys.argv)<3:
		print 'Usage ' + sys.argv[0] + ' interface ipaddress1,ipaddress2,...'
		sys.exit(0)

	HOST = 'localhost'
	PORT = 8001


	device=sys.argv[1]

	destinations=sys.argv[2:]

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

			''' PRINT PACKET '''
			print "##########################################################"
			print "Dati ricevuti: ",len(raw_buffer)

			#print "ETH HEADER: ",  srcMac,dstMac,ethType

			print "IP: ver" , ver,' header len ', h_len,' TOS ', service_field,' len ', total_length,' id ', identification
			print ' flag fr ' , flag_frag,' ttl ',ttl,' protocol ',protocol,' chksum ' , checkSum, ' src ' ,src_ip,' dst ' ,dst_ip


			#print "UDP: ", srcPort,dstPort,dataLenght,str("%0.4X" % tp_checksum)

			#print "Data: ",data


			#print "ETH Tr:" , binascii.hexlify(eth_trailer)


			#print 'Duplicating....'


			checkSum='0000'
			blank_checksum=binascii.unhexlify(checkSum)

			ip_ricalcolo=struct.pack('!1s1s1H1H2s1B1B2s4s4s' , iph[0],iph[1],iph[2],iph[3],iph[4],iph[5],iph[6],blank_checksum,iph[8],iph[9])
			ricalcolo=inet_utils.checksum_little_endian(ip_ricalcolo)
			print 'Received IP PKT Checksum ' , binascii.hexlify(iph[7]) , ' Recalculated IP PKT Checksum ' , str("%0.4X" % ricalcolo)

			packedIP = sck.inet_aton(src_ip)
			scr_long=struct.unpack("!L", packedIP)[0]
			packedIP = sck.inet_aton(dst_ip)
			dst_long=struct.unpack("!L", packedIP)[0]

			pseudo_udp=[0] * 4
			pseudo_udp[0]=scr_long
			pseudo_udp[1]=dst_long
			pseudo_udp[2] =  17
			pseudo_udp[3] = dataLenght

			#print type(iph[8])
			#print type(iph[9])
			#print type(dataLenght)

			

			#pseudo_udp_pkt = struct.pack('!4s4s1B1B1H',pseudo_udp[0],pseudo_udp[1],pseudo_udp[2],pseudo_udp[3],pseudo_udp[4])
			pseudo_udp_pkt = struct.pack('!LLxBH',pseudo_udp[0],pseudo_udp[1],pseudo_udp[2],pseudo_udp[3])

			udp_no_chk=udp_header_dup=struct.pack('!HHHH', udph[0],udph[1],udph[2],0)

			chksum_pkt = pseudo_udp_pkt+udp_no_chk+data

			udp_checksum=inet_utils.checksum_little_endian(chksum_pkt)

			#udp_checksum=udp_checksum+udph[1]+udph[2]

			print 'Received UDP PKT Checksum' ,str("%0.4X" % tp_checksum) , ' recalculated UDP PKT Checksum ' , str("%0.4X" % udp_checksum)





			for d in destinations:
				raw_duplication=[]

				#srcMac = binascii.hexlify(ethh[0])
				dstdumpMac = binascii.unhexlify('FFFFFFFFFFFF')
				#ethType = binascii.hexlify(ethh[2])

				eth_duplicate=struct.pack('!6s6s2s' , dstdumpMac,ethh[1],ethh[2])


				raw_duplication[0:14]=eth_duplicate

				
				
				dupdst=sck.inet_aton(d)
				packedIP = sck.inet_aton(src_ip)
				src_long=struct.unpack("!L", packedIP)[0]
				packedIP = sck.inet_aton(d)
				dst_long=struct.unpack("!L", packedIP)[0]

				print 'Sending to:',d
				
				#new_ip_header={iph[0],iph[1],iph[2],iph[3],iph[4],iph[5],iph[6],blank_checksum,iph[8],dupdst}


				#new_checksum=inet_utils.ip_checksum(new_ip_header,len(new_ip_header))

				#ip_duplicate=struct.pack('!1s1s1H1H2s1B1B2s4s4s' , iph[0],iph[1],iph[2],iph[3],iph[4],iph[5],iph[6],new_checksum,iph[8],dupdst)
				ip_pkt_no_chksum=struct.pack('!1s1s1H1H2s1B1B2s4s4s' , iph[0],iph[1],iph[2],iph[3],iph[4],iph[5],iph[6],blank_checksum,iph[8],dupdst)
				
				
				ip_chksum_pkt = struct.unpack('!HHHHHHHHHH',ip_pkt_no_chksum) 

				#code.interact(local=locals())
				
				new_checksum=inet_utils.checksum_big_endian(ip_chksum_pkt)

				print 'new ip checksum ' ,str("%0.4X" % new_checksum)

				#iph_no_check = struct.unpack('!1s1s1H1H2s1B1B2s4s4s' , ip_duplicate)
				


			
				#packedIP = sck.inet_aton(src_ip)
				#scr_long=struct.unpack("!L", packedIP)[0]
				#packedIP = sck.inet_aton(d)
				#dst_long=struct.unpack("!L", packedIP)[0]

				pseudo_udp=[0] * 4
				pseudo_udp[0]=scr_long
				pseudo_udp[1]=dst_long
				pseudo_udp[2] =  17
				pseudo_udp[3] = dataLenght
				pseudo_udp_pkt = struct.pack('!LLxBH',pseudo_udp[0],pseudo_udp[1],pseudo_udp[2],pseudo_udp[3])

				udp_no_chk=struct.pack('!HHHH', udph[0],udph[1],udph[2],0)

				chksum_pkt = pseudo_udp_pkt+udp_no_chk+data

				udp_checksum=inet_utils.checksum_little_endian(chksum_pkt)


				
				#str("%0.4X" % new_checksum)

				#ip_duplicate=struct.pack('!1s1s1H1H2s1B1B2s4s4s' , iph[0],iph[1],iph[2],iph[3],iph[4],iph[5],iph[6],str("%0.4X" % new_checksum),iph[8],dupdst)
				ip_duplicate=struct.pack('!1s1s1H1H2s1B1BH4s4s' , iph[0],iph[1],iph[2],iph[3],iph[4],iph[5],iph[6],new_checksum,iph[8],dupdst)
				#print len(ip_duplicate)

				#ip_str=struct.unpack('!HHHHHHHHHH' , ip_duplicate)
				#print ("%0.4X" % ip_str[6])
				
				#in posizione 6 -> il checksum																		cheksum
				#ip_duplicate=struct.pack('!HHHHHHHHHH',ip_str[0],ip_str[1],ip_str[2],ip_str[3],ip_str[4],ip_str[5],ip_str[6],ip_str[7],ip_str[8],ip_str[9])

				#i=0
				#for s in ip_str:
				#	if i==5:
				#		print ("%0.4X  *" % s)
				#	else:
				#		print ("%0.4X" % s)
				#	i=i+1
				




				#code.interact(local=locals())

			
				print 'new udp checksum ' ,str("%0.4X" % udp_checksum)
				udp_header_dup=struct.pack('!HHHH', udph[0],udph[1],udph[2],udp_checksum)

				raw_duplication[14:34]=ip_duplicate
				raw_duplication[34:42]=udp_header_dup
				raw_duplication[42:42+dataLenght]=data
				raw_duplication[42+dataLenght:]=eth_trailer	
				#print raw_duplication
				sock.sendall(str(bytearray(raw_duplication)))

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