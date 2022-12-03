
from scapy.all import *
import scapy.all as scapy
from scapy.layers import http
import atexit 
import matplotlib.pyplot as plt
import subprocess
from tkinter import *
import tkinter.messagebox
import requests
from colorama import Fore


def getmac(ip):

	arp_request_header = scapy.ARP(pdst = ip)
	ether_header = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_request_packet = ether_header/arp_request_header
	answered_list = scapy.srp(arp_request_packet,timeout=1,verbose=False)[0]
	return  answered_list[0][1].hwsrc





def scan_network(IPAddr):  #ON_BUUTON_CLICK
	jadu=[]
	jadu.append(IPAddr.split('.'))
	subnet_IP= jadu[0][0]+"."+jadu[0][1] +"."+jadu[0][2]+"."+"0/24"
	proc = subprocess.Popen(['nmap', '-sn', subnet_IP], stdout=subprocess.PIPE)
	output =proc.stdout.read()
	print output
	

def detect_attack(real_mac,response_mac):
	try:
                if real_mac != response_mac:
			global ATTACK_count
			ATTACK_count=ATTACK_count+1
			attack2_info= "You Are Under Attack"
			attack_info = " Router Mac adress has change from "+ str(real_mac) + " to "+ str(response_mac)
			win = Tk()
			win.geometry("750x240")
			Label(win, text= attack2_info,font=('Helvetica 13')).pack(pady=20)
			Label(win, text= attack_info,font=('Helvetica 13')).pack(pady=20)
			
			win.after(3000,lambda:win.destroy())

			win.mainloop()

	except IndexError:
		pass



def pkt_count():	
	global udp_count, icmp_count,tcp_count,http_count,ATTACK_count
	topic = ['UDP', 'ICMP', 'TCP', 'HTTP', 'ATTACK']
	Postive_percentage = []
	Postive_percentage.append(udp_count)
	Postive_percentage.append(icmp_count)
	Postive_percentage.append(tcp_count)
	Postive_percentage.append(http_count)
	Postive_percentage.append(ATTACK_count)
	sizes = Postive_percentage
	print(sizes)
	labels = list(topic)
	# makeitastring = ''.join(map(str, labels))
	print(labels)
	colors = ['yellowgreen', 'lightgreen', 'darkgreen', 'gold', 'red']
	plt.pie(sizes, explode=None, labels=labels, colors=colors, autopct='%1.1f%%', shadow=True, startangle=90)   #line 240
	#plt.pie(sizes, labels, colors)
	plt.axis('equal')
	plt.legend()
	plt.show()



def network_monitoring_for_visualization_version(pkt):
	#print pkt
	if pkt.haslayer(UDP):
		global udp_count
		udp_count=udp_count+1
		print ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>UDP PKT >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> "
		print pkt.show()
		

	if pkt.haslayer(TCP):
		global tcp_count
		tcp_count=tcp_count+1
		print ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>TCP PKT>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
		print pkt.show()
		
	
	if pkt.haslayer(http.HTTPRequest):
		global http_count
		http_count=http_count+1
		print ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>HTTP PACKET>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
		print "                                                                                                             "
		print "HTTP Request >>", pkt[http.HTTPRequest].Host + pkt[http.HTTPRequest].Path
		print "                                                                         "
		print "User_Agent >>",pkt[http.HTTPRequest].User_Agent
		try:
			#print "                                                                         "
			print "                                                                         "
			print ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>DATA>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
			print(pkt[Raw].load)
			print "                                                                         "
			print "                                                                         "
		except IndexError:
			print("None")
		

	
	if pkt.haslayer(scapy.ARP) and pkt[scapy.ARP].op==2:
		        try:	
				real_mac = getmac(pkt[scapy.ARP].psrc)
				response_mac = pkt[scapy.ARP].hwsrc
				detect_attack(real_mac,response_mac)
			except IndexError:
		                pass
			



if __name__ == '__main__':
	udp_count=0
	icmp_count=0
	tcp_count=0
	http_count=0
	ATTACK_count=50

	try :	
		ip = input("enter IP of network >>  ")
		scan_network(ip)
		packets= sniff(prn=network_monitoring_for_visualization_version)
		#file=file+wrpcap('/var/www/html/file.pcap>',packets)
		atexit.register(pkt_count)
	except KeyboardInterrupt:
		print("Exiting.......")
	

	 
		
