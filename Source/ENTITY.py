import socket
import re

class ENTITY:

	__message_identifier = None
	__destination_conns = None

	
	def __init__(self, destination_addresses):
		
		self.__message_identifier = 0
		self.__destination_conns = []

		for destination_ip in destination_addresses:
			if re.match("[0-9]+(?:\\.[0-9]+){3}", destination_ip):
				new_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				new_socket.connect((destination_ip, 12000))
				self.__destination_conns.append(new_socket)
			else:
				print("WARNING: INVALID IP (" + destination_ip + ")")


	def shutdown(self):

		for conn in self.destination_conns:
			conn.close()


	def send(packet):

		ft_packet = len(packet).to_bytes(2, byteorder='big') + self.__message_identifier.to_bytes(4, byteorder='big') + packet
		self.__message_identifier += 1

		eliminate = []
		for conn in self.__destination_conns:
			try:
				conn.sendall(dummy_packet)
			except:
				eliminate.append(conn)

		if len(eliminate) > 0:
			for conn in eliminate:
				print("WARNING: CONNECTION FAILED AND REMOVED (" + conn.getpeername() + ")")
				conn.close()
				destination_conns.remove(conn)