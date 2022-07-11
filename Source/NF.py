import multiprocessing
import re

import NSH
import NM

class NF:

	__memory_manager = None
	__pkt_list = None
	__pkt_mutex = None
	__pkt_semaphore = None

	__nsh_processor = None
	__ft_manager = None

	__nf_acc_address = None
	__ft_checking = None
	__client_control = None


	def __init__(self, nf_acc_address, ft_checking ):

		self.__nf_acc_address = nf_acc_address
		try:
			self.__ft_checking = int(ft_checking)
		except:
			print("ERROR: INVALID ft_checking PROVIDED!")
			exit()

		if not self.__isIP(self.__nf_acc_address):
			print("ERROR: INVALID IP PROVIDED!")
			exit()

		self.__memory_manager = multiprocessing.Manager()
		self.__pkt_manager = multiprocessing.Manager()
		self.__pkt_list = self.__pkt_manager.list()
		self.__pkt_mutex = self.__pkt_manager.Lock()
		self.__pkt_semaphore = self.__pkt_manager.Semaphore(0)

		self.__nsh_processor = NSH.NSH()
		self.__ft_manager = NM.NET_MANAGER(self.__nf_acc_address, self.__pkt_list, self.__pkt_mutex, self.__pkt_semaphore, True)
		self.__ft_manager.startServer()

		self.__client_control = {}


	def __isIP(self, potential_ip):
		return re.match("[0-9]+(?:\\.[0-9]+){3}", potential_ip.lower())


	def function(self, packet):
		return packet


	def run(self):

		while True:
			self.__pkt_semaphore.acquire()
			self.__pkt_mutex.acquire()
			recv_data = self.__pkt_list.pop(0)
			self.__pkt_mutex.release()

			if recv_data[2] == -1:
				if recv_data[3] in self.__client_control:
					del self.__client_control[recv_data[3]]
					continue

			try:
				self.__nsh_processor.fromHeader(recv_data[0][14:][:-len(recv_data[0]) + 38])
			except:
				continue

			if not recv_data[3] in self.__client_control:
				self.__client_control[recv_data[3]] = {'control':-1}

			if self.__client_control[recv_data[3]]['control'] >= recv_data[2]:
				continue

			if not recv_data[2] in self.__client_control[recv_data[3]]:
				if self.__ft_checking > 1:
					self.__client_control[recv_data[3]][recv_data[2]] = [[recv_data[0], 1]]
				else:
					self.__nsh_processor.service_si += 1
					self.__ft_manager.broadcastMessage(len(recv_data[0]).to_bytes(2, byteorder='big') + recv_data[2].to_bytes(4, byteorder='big') + recv_data[0][:-len(recv_data[0])+14] + self.__nsh_processor.toHeader() + recv_data[0][38:])
				continue

			found_flag = False
			for index in range(len(self.__client_control[recv_data[3]][recv_data[2]])):
				if self.__client_control[recv_data[3]][recv_data[2]][index][0] == recv_data[0]:
					self.__client_control[recv_data[3]][recv_data[2]][index][1] += 1
					found_flag = True
					break

			if not found_flag:
				self.__client_control[recv_data[3]][recv_data[2]].append([recv_data[0], 1])
				continue

			if self.__client_control[recv_data[3]][recv_data[2]][index][1] == self.__ft_checking:
				self.__nsh_processor.service_si += 1
				processed_packet = recv_data[2].to_bytes(4, byteorder='big') + recv_data[0][:-len(recv_data[0])+14] + self.__nsh_processor.toHeader() + self.function(recv_data[0][38:])
				self.__ft_manager.broadcastMessage(len(processed_packet).to_bytes(2, byteorder='big') + processed_packet)
				self.__client_control[recv_data[3]]['control'] = recv_data[2]
				del self.__client_control[recv_data[3]][recv_data[2]]