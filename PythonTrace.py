#!/usr/bin/python

import socket
import sys
import subprocess
import shlex
import csv
import string

def main(dest_name):
	dest_addr = socket.gethostbyname(dest_name)
	icmp = socket.getprotobyname('icmp')
	udp = socket.getprotobyname('udp')
	socket.setdefaulttimeout(3.0)
	port = 33434
	max_hops = 30
	ttl = 1
	while True:
		recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
		send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)
		send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
		recv_socket.bind(("", port))
		send_socket.sendto(b"", (dest_name, port))
		curr_addr = None
		curr_name = None
		try:
			_, curr_addr = recv_socket.recvfrom(512)
			curr_addr = curr_addr[0]
			try:
				curr_name = socket.gethostbyaddr(curr_addr)[0]
			except socket.error:
				curr_name = curr_addr
		except socket.error:
			pass
		finally:
			send_socket.close()
			recv_socket.close()
		if curr_addr is not None:
			curr_host = "%s (%s)" % (curr_name, curr_addr)
			ip_bytes = curr_addr.split('.')
			ip_r = '.'.join(reversed(ip_bytes))
			cmd = 'dig +short ' + ip_r  + '.origin.asn.cymru.com TXT'
		else:
			curr_host = "*"
			query = "*"
		print (ttl,"\t",curr_host)
		proc = subprocess.Popen(shlex.split(cmd), stdout = subprocess.PIPE)
		for ln in proc.stdout:
			print(ln.decode(), end='')
		ttl += 1
		if curr_addr == dest_addr or ttl > max_hops:
			break

if __name__ == "__main__":
	main(sys.argv[1])
