#!/usr/bin/python -O

"""
[Amun - low interaction honeypot]
Copyright (C) [2008]  [Jan Goebel]

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, see <http://www.gnu.org/licenses/>
"""

__author__ = "jan goebel"
__version__ = "0.1.9"

try:
	import psyco ; psyco.full()
	from psyco.classes import *
except ImportError:
	pass

import asynchat
import asyncore
import sys
import socket
import traceback
import StringIO
import time
import select
import logging
import logging.handlers
import gc
import os
import re

import optparse

import subprocess
import hashlib

### NOTICE: local imports at the bottom ###

class amunServer(asynchat.async_chat):

	def __init__(self, address, type, currentSockets, decodersDict, event_dict, vuln_modules, divLogger, config_dict):
		asynchat.async_chat.__init__(self)
		self.address = address
		self.divLogger = divLogger
		self.log_obj = amun_logging.amun_logging("amun_server", divLogger['amunServer'])
		self.decodersDict = decodersDict
		self.currentSockets = currentSockets
		self.vuln_modules = vuln_modules
		self.currentConnections = {}
		self.reconnectMap = {}
		self.lastCheck = int(time.time())
		self.numFiles = 0
		self.event_dict = event_dict
		self.config_dict = config_dict
		self.replace_locals = config_dict['replace_locals']
		socket.setdefaulttimeout(60.0)
		if type=="tcp":
			self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
		elif type=="udp":
			self.create_socket(socket.AF_INET, socket.SOCK_DGRAM)
		else:
			self.log_obj.log("passed invalid server type", 0, "crit", True, True)
			sys.exit(1)
		self.set_reuse_addr()
		try:
			self.bind(self.address)
		except socket.error, e:
			if int(e[0])==98:
				self.log_obj.log("Port already in use: IP: %s Port: %s" % (self.address[0], self.address[1]), 0, "crit", True, True)
			else:
				print "amun_server socket error:"
				print e
				raise
		except:
			print "amun_server bind error:"
			print self.address
			raise
		if type=="tcp":
			self.listen(1)
		if config_dict['verbose_logging'] == 1:
			self.log_obj.log("listening on %s port %s" % (type, address[1]), 0, "debug", False, True)
	
	def handle_accept(self):
		### accept connection
		try:
			(sock_obj, addr) = self.accept()
			### check for blocked ips
			try:
				time = self.event_dict['refused_connections'][str(addr[0])]
				return
			except KeyError:
				pass
			try:
				time = self.event_dict['timeout_connections'][str(addr[0])]
				return
			except KeyError:
				pass
			try:
				time = self.event_dict['sucdown_connections'][str(addr[0])]
				return
			except KeyError:
				pass
			try:
				time = self.event_dict['sucexpl_connections'][str(addr[0])]
				return
			except KeyError:
				pass
			handler = amun_request_handler.amun_reqhandler(self.divLogger).handle_incoming_connection(
											sock_obj,
											self.currentSockets,
											self.currentConnections,
											self.decodersDict,
											self.event_dict,
											self.config_dict,
											self.vuln_modules,
											self.divLogger,
											addr)
		except KeyboardInterrupt:
			raise
		except:
			pass

	def handle_connect(self):
		return

	def handle_read(self):
		### udp connections come in here
		### directly send to shellcodemanager
		shellcode_manager = shellcode_mgr_core.shell_mgr(self.decodersDict, self.divLogger['shellcode'], self.config_dict)
		try:
			data, address = self.recvfrom(64*1024)
			if len(data)>4:
				remote_ip = address[0]
				remote_port = address[1]
				vulnResult = {}
				vulnResult['vulnname'] = "UDP"
				vulnResult['shellcode'] = data
				result = shellcode_manager.start_matching(vulnResult,remote_ip,self.address[0],self.address[1],self.replace_locals,False)
				if result['result']:
					identifier = "%s%s%s%s" % (remote_ip, remote_port, self.address[0], self.address[1])
					### create exploit event
					event_item = (remote_ip,
							remote_port,
							self.address[0],
							self.address[1],
							'UDP Vulnerability',
							int(time.time()),
							result)
					if not self.event_dict['exploit'].has_key(identifier):
						self.event_dict['exploit'][identifier] = event_item
					### attach to download events
					if not self.event_dict['download'].has_key(identifier):
						self.event_dict['download'][identifier] = result
				else:
					self.log_obj.log("received unknown UDP request", 0, "debug", True, True)
			else:
				self.log_obj.log("UDP size too small", 0, "debug", True, True)
		except:
			self.log_obj.log("error in UDP handle_read", 0, "crit", True, True)

	def writable(self):
		return False

	def readable(self):
		return True

	def handle_error(self):
		self.log_obj.log("handle_error", 0, "crit", True, True)
		f = StringIO.StringIO()
		traceback.print_exc(file=f)
		self.log_obj.log(f.getvalue(), 0, "crit", True, True)
		self.close()
		raise


def log(message, tabs=0, type="normal", Logger=None, display=True):
	try:
		empty = ""
		for i in xrange(0, tabs):
			empty += " "
	
		if display:
			if type=="debug":
				print "\033[0;34m%s.::[Amun - Main] %s ::.\033[0m" % (empty, message)
			elif type=="warn":
				print "\033[0;33m%s.::[Amun - Main] %s ::.\033[0m" % (empty, message)
			elif type=="info":
				print "\033[0;32m%s.::[Amun - Main] %s ::.\033[0m" % (empty, message)
			elif type=="crit":
				print "\033[0;31m%s.::[Amun - Main] %s ::.\033[0m" % (empty, message)
			elif type=="fade":
				print "\033[0;37m%s.::[Amun - Main] %s ::.\033[0m" % (empty, message)
			elif type=="div":
				print "\033[0;36m%s.::[Amun - Main] %s ::.\033[0m" % (empty, message)
			else:
				print "\033[0m%s.::[Amun - Main] %s ::.\033[0m" % (empty, message)
		if Logger:
			Logger.info(message)
	except KeyboardInterrupt:
		raise

def check_idle_connections(currentSockets, connection_timeout, event_dict, serverLogger, config_dict):
	### check idle connections
	try:
		conn_keys = currentSockets.keys()
		for key in conn_keys:
			current_time = int(time.time())
			conn_time = currentSockets[key][0]
			difference = current_time - conn_time
			if difference >= connection_timeout:
				try:
					(attIP, attPort) = currentSockets[key][1].getpeername()
					if config_dict['block_timeout']==1:
						block_item = str(attIP)
						event_dict['timeout_connections'][block_item] = int(time.time())
					currentSockets[key][1].shutdown(socket.SHUT_RDWR)
					if config_dict['verbose_logging'] == 1:
						log("sending shutdown to idle connection (idle: %s IP: %s)" % (difference, attIP), 9, "debug", serverLogger, True)
					if event_dict['initial_connections'].has_key(key):
						del event_dict['initial_connections'][key]
				except socket.error, e:
					if e[0]==9:
						log("shutdown non-existant socket", 9, "crit", None, False)
					elif e[0]==107:
						log("transport endpoint is not connected", 9, "crit", None, False)
					else:
						log("shutdown socket error: %s (%s)" % (e, len(conn_keys)), 9, "crit", serverLogger, True)
					if currentSockets.has_key(key):
						del currentSockets[key]
					if event_dict['initial_connections'].has_key(key):
						del event_dict['initial_connections'][key]
	except KeyboardInterrupt:
		raise

def check_download_events(event_dict, config_dict, currentDownloads, bindports, tftp_downloads, divLogger, currentSockets, ftp_downloads, decodersDict):
	### check for download events
	try:
		downl_keys = event_dict['download'].keys()
		for key in downl_keys:
			item = event_dict['download'][key]
			if item['dlident'] == "None":
				log("item is missing identifier: %s" % (item), 0, "crit", divLogger['unknownDownload'], True)
			del event_dict['download'][key]
			if currentDownloads.has_key(item['dlident']):
				continue
			if item['isLocalIP']:
				if config_dict['log_local_downloads']:
					log("item with localIP, skipping download: %s" % (item), 0, "info", divLogger['unknownDownload'], False)
				continue
			if item['found']=="httpurl":
				### HTTP Downloads
				currentDownloads[item['dlident']] = int(time.time())
				d = download_core.download_http(item, currentDownloads, event_dict, config_dict, currentSockets, divLogger['download'])
			elif item['found']=="bindport":
				### BindPort
				currentDownloads[item['dlident']] = int(time.time())
				d = bindport_core.bindPort(item, currentDownloads, bindports, event_dict, divLogger, config_dict, currentSockets, decodersDict)
			elif item['found']=="connectbackfiletrans":
				### ConnectBack Filetransfer
				currentDownloads[item['dlident']] = int(time.time())
				d = download_core.download_connectback(item, currentDownloads, currentSockets, divLogger, event_dict, config_dict, False, item['passwort'], decodersDict)
			elif item['found']=="connbackshell":
				### ConnectBack Shell
				currentDownloads[item['dlident']] = int(time.time())
				d = download_core.download_connectback(item, currentDownloads, currentSockets, divLogger, event_dict, config_dict, True, "None", decodersDict)
			elif item['found']=="tftp":
				### TFTP Downloads
				currentDownloads[item['dlident']] = int(time.time())
				d = tftp_download_core.tftp(item, currentDownloads, tftp_downloads, event_dict, divLogger['download'], config_dict)
			elif item['found']=="ftp":
				### FTP Downloads
				currentDownloads[item['dlident']] = int(time.time())
				d = ftp_download_core.download_ftp(item, currentDownloads, event_dict, config_dict, ftp_downloads, divLogger['download'], currentSockets)
			else:
				### Unknown Download Event
				log("unknown item: %s" % (item), 0, "info", divLogger['unknownDownload'], False)
			del d
	except KeyboardInterrupt:
		raise

def check_refused_ips(event_dict, refused_timeout, serverLogger, verbose_logging):
	### check refused ips
	try:
		refused_keys = event_dict['refused_connections'].keys()
		for key in refused_keys:
			logged_time = event_dict['refused_connections'][key]
			current_time = int(time.time())
			difference = current_time - int(logged_time)
			if difference >= refused_timeout:
				del event_dict['refused_connections'][key]
				if verbose_logging==1:
					log("removing refused IP %s (blocktime: %s)" % (key, difference), 0, "debug", serverLogger, True)
	except KeyboardInterrupt:
		raise

def check_timeout_ips(event_dict, timeout_blocktime, serverLogger, verbose_logging):
	### check timeouted ips
	try:
		timeouted_keys = event_dict['timeout_connections'].keys()
		for key in timeouted_keys:
			logged_time = event_dict['timeout_connections'][key]
			current_time = int(time.time())
			difference = current_time - int(logged_time)
			if difference >= timeout_blocktime:
				del event_dict['timeout_connections'][key]
				if verbose_logging==1:
					log("removing timeouted IP %s (blocktime: %s)" % (key, difference), 0, "debug", serverLogger, True)
	except KeyboardInterrupt:
		raise

def check_sucdown_ips(event_dict, sucdown_blocktime, serverLogger, verbose_logging):
	### check successfull download ips
	try:
		sucdown_keys = event_dict['sucdown_connections'].keys()
		for key in sucdown_keys:
			logged_time = event_dict['sucdown_connections'][key]
			current_time = int(time.time())
			difference = current_time - int(logged_time)
			if difference >= sucdown_blocktime:
				del event_dict['sucdown_connections'][key]
				if verbose_logging==1:
					log("removing successfull download IP %s (blocktime: %s)" % (key, difference), 0, "debug", serverLogger, True)
	except KeyboardInterrupt:
		raise

def check_sucexpl_ips(event_dict, sucexpl_blocktime, serverLogger, verbose_logging):
	### check successfull exploit ips
	try:
		sucexpl_keys = event_dict['sucexpl_connections'].keys()
		for key in sucexpl_keys:
			logged_time = event_dict['sucexpl_connections'][key]
			current_time = int(time.time())
			difference = current_time - int(logged_time)
			if difference >= sucexpl_blocktime:
				del event_dict['sucexpl_connections'][key]
				if verbose_logging==1:
					log("removing successfull exploit IP %s (blocktime: %s)" % (key, difference), 0, "debug", serverLogger, True)
	except KeyboardInterrupt:
		raise

def check_for_initial_connection_event(event_dict, exLogger, log_modules, loLogger, currentSockets, serverLogger, verbose_logging):
	### check for initial connection events
	try:
		init_keys = event_dict['initial_connections'].keys()
		for key in init_keys:
			item = event_dict['initial_connections'][key]
			if item[5] == 1:
				currentTime = int(time.time())
				difference = currentTime - item[6]
				### TODO: timeout in config
				if difference>300:
					del item
					del event_dict['initial_connections'][key]
					if verbose_logging==1:
						log("removing initial connection entry (waittime: %s)" % (difference), 0, "debug", serverLogger, True)
				continue
			### item[0] => attackerIP
			### item[1] => attackerPort
			### item[2] => victimIP
			### item[3] => victimPort
			### item[4] => attackerID storage place
			### item[5] => integer if checked or not
			[module.initialConnection(item[0], item[1], item[2], item[3], key, event_dict['initial_connections'], loLogger) for module in log_modules]
			event_dict['initial_connections'][key][5] = 1
			#if not currentSockets.has_key(key):
			#	del event_dict['initial_connections'][key]
	except KeyboardInterrupt:
		raise

def check_for_exploit_event(event_dict, exLogger, log_modules, loLogger):
	### check for exploit events
	try:
		expl_keys = event_dict['exploit'].keys()
		for key in expl_keys:
			item = event_dict['exploit'][key]
			del event_dict['exploit'][key]
			### item[0] => Attacker IP
			### item[1] => Attacker Port
			### item[2] => Victim IP
			### item[3] => Victim Port
			### item[4] => Vulnerability Name
			### item[5] => Timestamp
			### item[6]['found'] => Download Method
			### item[6]['displayURL'] => Download URL
			### item[6]['shellcodeName'] => Sellcode Name
			log("exploit %s:%s -> %s:%s (%s: %s) (Shellcode: %s)" % (item[0],item[1],item[2],item[3],item[4],item[6]['displayURL'],item[6]['shellcodeName']), 0, "normal", exLogger, False)
			### generate identifier to get attackID
			identifier = "%s%s%s%s" % (item[0],item[1],item[2],item[3])
			if event_dict['initial_connections'].has_key(identifier):
				attackerID = event_dict['initial_connections'][identifier][4]
				del event_dict['initial_connections'][identifier]
			else:
				#print "no id"
				attackerID = None
			### iterate over logging modules
			[module.incoming(item[0],item[1],item[2],item[3],item[4],item[5],item[6]['displayURL'], loLogger, attackerID, item[6]['shellcodeName']) for module in log_modules]
	except KeyboardInterrupt:
		raise

def check_for_succ_download_event(event_dict, suLogger, submit_modules, smLogger, block_sucdown, lastBinaries, log_modules, loLogger):
	### check for successfull download events
	try:
		dwl_keys = event_dict['successfull_downloads'].keys()
		for key in dwl_keys:
			item = event_dict['successfull_downloads'][key]
			### item[0] => data length
			### item[1] => attacker IP
			### item[2] => attacker Port
			### item[3] => victim IP
			### item[4] => download method
			### item[5] => binary data
			### item[6] => vulnerability name
			### item[7] => download URL
			del event_dict['successfull_downloads'][key]
			data = item[5]
			data_len = item[0]
			### check file header for misc bytes
			if data_len >= 5:
				(data, data_len) = check_file(data, data_len, suLogger)
			hash = hashlib.md5(data)
			fname = hash.hexdigest()
			### check if file is already stored
			fexists = False
			if lastBinaries.contains(fname):
				fexists = True
			else:
				check_filename = "malware/md5sum/%s.bin" % (fname)
				if os.path.exists(check_filename):
					fexists = True
				lastBinaries.insert(fname)
			### check for error download
			if not fexists and data_len<=50:
				errorResult = check_file_for_error(data, data_len, suLogger)
				if errorResult:
					continue
			### log download event
			log("download (%s): %s (size: %i) - %s:%i - %s" % (item[7], fname, data_len, item[1], item[2], item[6].replace(' Vulnerability','')), 0, "normal", suLogger, False)
			### block hosts with successfull download for some time
			if block_sucdown == 1:
				block_item = str(item[1])
				event_dict['sucdown_connections'][block_item] = int(time.time())
			### iterate over log modules that also log submission
			[module.successfullSubmission(item[1], item[2], item[3], item[7], fname, data, data_len, item[4], loLogger, item[6], fexists) for module in log_modules]
			### iterate over submission modules
			[module.incoming(data, data_len, item[4], item[1], item[3], smLogger, fname, item[2], item[6], item[7], fexists) for module in submit_modules]
	except KeyboardInterrupt:
		raise


def check_file_for_error(data, data_len, suLogger):
	try:
		### compile regular expressions
		fileDirnotfoundExpre = re.compile("\\x4e\\x6f\\x20\\x73\\x75\\x63\\x68\\x20\\x66\\x69\\x6c\\x65\\x20\\x6f\\x72\\x20\\x64\\x69\\x72\\x65\\x63\\x74\\x6f\\x72\\x79", re.S)
		filenotfoundExpre = re.compile("\\x46\\x69\\x6c\\x65\\x20\\x4e\\x6f\\x74\\x20\\x46\\x6f\\x75\\x6e\\x64", re.S)
		filenotfoundExpre2 = re.compile("\\x46\\x69\\x6c\\x65\\x20\\x6e\\x6f\\x74\\x20\\x66\\x6f\\x75\\x6e\\x64", re.S)
		illegalTFTP = re.compile("\\x69\\x6c\\x6c\\x65\\x67\\x61\\x6c\\x20\\x54\\x46\\x54\\x50\\x20\\x6f\\x70\\x65\\x72\\x61\\x74\\x69\\x6f\\x6e\\x2e", re.S)
		getNotSupp = re.compile("\\x47\\x65\\x74\\x20\\x6e\\x6f\\x74\\x20\\x73\\x75\\x70\\x70\\x6f\\x72\\x74\\x65\\x64")
		### check for matches
		match = fileDirnotfoundExpre.search(data)
		if match:
			log("received: file or directory not found", 0, "debug", suLogger, False)
			return True
		match = filenotfoundExpre.search(data)
		if match:
			log("received: file or directory not found", 0, "debug", suLogger, False)
			return True
		match = filenotfoundExpre2.search(data)
		if match:
			log("received: file or directory not found", 0, "debug", suLogger, False)
			return True
		match = illegalTFTP.search(data)
		if match:
			log("received: illegal tftp operation", 0, "debug", suLogger, False)
			return True
		match = getNotSupp.search(data)
		if match:
			log("received: get not supported", 0, "debug", suLogger, False)
			return True
		return False
	except KeyboardInterrupt:
		raise

def check_file(data, data_len, suLogger):
	### check if misc data is in the beginning of the file
	try:
		i = 0
		found = False
		### if it starts with MZ everything is fine
		if data[i]=='\x4d' and data[i+1]=='\x5a':
			return data, data_len
		### otherwise cut leading part
		while i <= data_len-4:
			if data[i]=='\x4d' and data[i+1]=='\x5a' and data[i+2]=='\x90' and data[i+3]=='\x00' and data[i+4]=='\x03':
				found = True
				break
			elif data[i]=='\x4d' and data[i+1]=='\x5a' and data[i+2]=='\x50' and data[i+3]=='\x00' and data[i+4]=='\x02':
				found = True
				break
			elif data[i]=='\x4d' and data[i+1]=='\x5a' and data[i+2]=='\x4b' and data[i+3]=='\x45' and data[i+4]=='\x52':
				found = True
				break
			elif data[i]=='\x4d' and data[i+1]=='\x5a' and data[i+2]=='\x66' and data[i+3]=='\x61' and data[i+4]=='\x72':
				found = True
				break
			elif data[i]=='\x4d' and data[i+1]=='\x5a' and data[i+2]=='\x00' and data[i+3]=='\x00' and data[i+4]=='\x00':
				found = True
				break
			elif data[i]=='\x4d' and data[i+1]=='\x5a' and data[i+2]=='\x90' and data[i+3]=='\xeb' and data[i+4]=='\x01':
				found = True
				break
			elif data[i]=='\x4d' and data[i+1]=='\x5a' and data[i+2]=='\x4c' and data[i+3]=='\x6f' and data[i+4]=='\x61':
				found = True
				break
			i += 1
		if i>0 and found:
			if i>5:
				log("cutting header (size: %i)" % (i), 0, "crit", suLogger, False)
			data = data[i:]
			data_len = len(data)
		return data, data_len
	except KeyboardInterrupt:
		raise

def check_idle_bindports(bindports, bind_timeout):
	### check idle bindports
	try:
		bind_keys = bindports.keys()
		for key in bind_keys:
			(ip,port,start_time) = bindports[key].split(',')
			current_time = int(time.time())
			difference = current_time - int(start_time)
			if difference >= bind_timeout:
				try:
					oSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
					oSocket.connect( (ip,int(port)) )
					oSocket.send('local quit')
					oSocket.shutdown(socket.SHUT_RDWR)
					oSocket.close()
					if bindports.has_key(key):
						del bindports[key]
				except socket.error, e:
					if e[0]!=111:
						log("bindport close failure: %s" % (e), 0, "crit", None, True)
					else:
						### connection refused -> port already closed
						pass
					if bindports.has_key(key):
						del bindports[key]
	except KeyboardInterrupt:
		raise

def check_idle_tftp_downloads(tftp_downloads, tftp_timeout):
	### check idle tftp downloads
	try:
		tftp_keys = tftp_downloads.keys()
		for key in tftp_keys:
			(port,start_time,ip) = tftp_downloads[key].split(',')
			current_time = int(time.time())
			difference = current_time - int(start_time)
			if difference >= tftp_timeout:
				try:
					oSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
					oSocket.sendto('resend', (ip, int(port)))
					oSocket.close()
				except socket.error, e:
					log("tftp download close failure: %s" % (e), 0, "crit", None, True)
					if tftp_downloads.has_key(key):
						del tftp_downloads[key]
	except KeyboardInterrupt:
		raise

def check_idle_ftp_downloads(ftp_downloads, ftp_timeout):
	### check idle ftp downloads
	try:
		ftp_keys = ftp_downloads.keys()
		for key in ftp_keys:
			(port, start_time, ip) = ftp_downloads[key].split(',')
			current_time = int(time.time())
			difference = current_time - int(start_time)
			if difference >= ftp_timeout:
				try:
					oSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
					oSocket.connect( (ip,int(port)) )
					oSocket.send('local quit')
					oSocket.close()
					if ftp_downloads.has_key(key):
						del ftp_downloads[key]
				except socket.error, e:
					if e[0]!=111:
						log("ftp download close failure: %s" % (e), 0, "crit", None, True)
					else:
						### connection refused -> port already closed
						pass
					if ftp_downloads.has_key(key):
						del ftp_downloads[key]
	except KeyboardInterrupt:
		raise

def readVulnModules(config, display=True):
	modules = config.getListValues("vuln_modules")
	vuln_modules = {}
	for module in modules:
		mod_name = module.strip()
		if display:
			log("loading vulnerability modul %s" % (mod_name), 0, "info", None, True)
		import_path = "vuln_modules/%s" % (mod_name)
		sys.path.append(import_path)
		import_name = "%s_modul" % (mod_name.replace('vuln-',''))
		import_name = __import__(import_name)
		port_list = config.getSingleValue(mod_name).split(',')
		for port in port_list:
			if vuln_modules.has_key(port):
				mod_list = vuln_modules[port]
				k = len(mod_list)
				mod_list[k] = import_name
			else:
				mod_list = {}
				mod_list[0] = import_name
			vuln_modules[port] = mod_list
	return vuln_modules

def readSubmitModules(config):
	modules = config.getListValues("submit_modules")
	submit_modules = []
	for module in modules:
		mod_name = module.strip()
		log("loading submission modul %s" % (mod_name), 0, "info", None, True)
		import_path = "submit_modules/%s" % (mod_name)
		sys.path.append(import_path)
		import_name = "submit_%s" % (mod_name.replace('submit-',''))
		import_name = __import__(import_name)
		submit_modules.append(import_name.submit())
	return submit_modules

def readLogModules(config):
	modules = config.getListValues("log_modules")
	log_modules = []
	for module in modules:
		mod_name = module.strip()
		log("loading logging modul %s" % (mod_name), 0, "info", None, True)
		import_path = "log_modules/%s" % (mod_name)
		sys.path.append(import_path)
		import_name = "log_%s" % (mod_name.replace('log-',''))
		import_name = __import__(import_name)
		log_modules.append(import_name.log())
	return log_modules

def checkServers(serverList, vuln_modules, divLogger, amunServerIPList, currentSockets, decodersDict, event_dict, config_dict, config, refused_blocktime, connection_timeout, bindport_timeout, ftp_timeout, tftp_retransmissions, timeout_blocktime, sucdown_blocktime, sucexpl_blocktime):
	### iterate over all running tcp servers
	current_time = int(time.time())
	last_check = int(config_dict['last_check'])
	difference = current_time - last_check
	if difference>=int(config_dict['check_new_vulns']):
		config_dict['last_check'] = int(time.time())
		### reload configuration
		if not config.reloadConfig():
			log("failed config reload", 0, "crit", divLogger['amunServer'], True)
			return serverList,vuln_modules,refused_blocktime,connection_timeout,bindport_timeout,ftp_timeout,tftp_retransmissions,timeout_blocktime,sucdown_blocktime,sucexpl_blocktime

		### update configuration parameters
		config_dict['check_new_vulns'] = int(config.getSingleValue("check_new_vulns"))
		config_dict['block_refused'] = int(config.getSingleValue("block_refused"))
		config_dict['block_timeout'] = int(config.getSingleValue("block_timeout"))
		config_dict['block_sucdown'] = int(config.getSingleValue("block_sucdown"))
		config_dict['block_sucexpl'] = int(config.getSingleValue("block_sucexpl"))
		config_dict['replace_locals'] = int(config.getSingleValue("replace_local_ip"))
		config_dict['store_unfinished_tftp'] = int(config.getSingleValue("store_unfinished_tftp"))
		config_dict['check_http_filesize'] = int(config.getSingleValue("check_http_filesize"))
		config_dict['tftp_max_retransmissions'] = int(config.getSingleValue("tftp_max_retransmissions"))
		config_dict['log_local_downloads'] = int(config.getSingleValue("log_local_downloads"))
		config_dict['ftp_port_range'] = config.getSingleValue("ftp_port_range")

		ftp_nat_ip = config.getSingleValue("ftp_nat_ip")
		if ftp_nat_ip!="None":
			ipReg = re.compile("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
			match = ipReg.search(ftp_nat_ip)
			if not match:
				ftp_nat_ip = socket.gethostbyaddr(ftp_nat_ip)[2][0]
		#config_dict['ftp_nat_ip'] = config.getSingleValue("ftp_nat_ip")
		config_dict['ftp_nat_ip'] = ftp_nat_ip

		config_dict['verbose_logging'] = int(config.getSingleValue("verbose_logging"))
		### get some global timeout parameters
		n_refused_blocktime = int(config.getSingleValue("refused_blocktime"))
		n_timeout_blocktime = int(config.getSingleValue("timeout_blocktime"))
		n_sucdown_blocktime = int(config.getSingleValue("sucdown_blocktime"))
		n_sucexpl_blocktime = int(config.getSingleValue("sucexpl_blocktime"))
		n_connection_timeout = int(config.getSingleValue("connection_timeout"))
		n_bindport_timeout = int(config.getSingleValue("bindport_timeout"))
		n_ftp_timeout = int(config.getSingleValue("ftp_timeout"))
		n_tftp_retransmissions = int(config.getSingleValue("tftp_retransmissions"))
		### get debug options
		output_curr_sockets = int(config.getSingleValue("output_curr_sockets"))
		if output_curr_sockets==1:
			fp = open("current_listed_sockets.txt", "w")
			curr_keys = currentSockets.keys()
			for key in curr_keys:
				try:
					(attIP, attPort) = currentSockets[key][1].getpeername()
					line = "%s:%s\n" % (attIP,attPort)
					fp.write(line)
				except socket.error, e:
					pass
			fp.close()

		### read current vulnerability configuration
		up_vuln_modules = readVulnModules(config, display=False)
		up_portList = up_vuln_modules.keys()

		newServerList = {}
		curr_portList = []
		### check if server needs to be removed
		for server in serverList.values():
			port = str(server.address[1])
			curr_portList.append(port)
			if not port in up_portList:
				log("closing server on port %s" % (port), 0, "warn", divLogger['amunServer'], True)
				server.close()
			else:
				newServerList[port] = server
		### check if server needs to be added
		for port in up_portList:
			if not port in curr_portList:
				log("starting new server on port %s" % (port), 0, "warn", divLogger['amunServer'], True)
				for amun_server_ip in amunServerIPList:
					server = amunServer((amun_server_ip,int(port)), "tcp", currentSockets, decodersDict, event_dict, up_vuln_modules, divLogger, config_dict)
					newServerList[port] = server
					del server

		### check for differences in vulnmodules
		for port in up_portList:
			try:
				newMods = up_vuln_modules[port]
				curMods = vuln_modules[port]
				if curMods != newMods:
					### restart server with port
					server = newServerList[port]
					server.close()
					log("restarting server on port %s" % (port), 0, "warn", divLogger['amunServer'], True)
					for amun_server_ip in amunServerIPList:
						server = amunServer( (amun_server_ip, int(port) ), "tcp", currentSockets, decodersDict, event_dict, up_vuln_modules, divLogger, config_dict)
						newServerList[port] = server
						del server
			except KeyError:
				pass
		### remove some references
		del curr_portList
		del up_portList
		del newMods
		del curMods
		### return updated lists
		return newServerList,up_vuln_modules,n_refused_blocktime,n_connection_timeout,n_bindport_timeout,n_ftp_timeout,n_tftp_retransmissions,n_timeout_blocktime,n_sucdown_blocktime,n_sucexpl_blocktime
	else:
		return serverList,vuln_modules,refused_blocktime,connection_timeout,bindport_timeout,ftp_timeout,tftp_retransmissions,timeout_blocktime,sucdown_blocktime,sucexpl_blocktime
	


def createUnknownDownloadLogFile():
	### create unknown download logfile
	logfile = "logs/unknown_downloads.log"
	ukLogger = logging.getLogger("amun-ud")
	#hdlr = logging.FileHandler(logfile)
	hdlr = logging.handlers.TimedRotatingFileHandler(logfile, 'midnight')
	formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
	hdlr.setFormatter(formatter)
	ukLogger.addHandler(hdlr)
	ukLogger.setLevel(10)
	return ukLogger

def createSucDownloadLogFile():
	### create successfull download logfile
	logfile = "logs/successfull_downloads.log"
	suLogger = logging.getLogger("amun-su")
	#hdlr = logging.FileHandler(logfile)
	hdlr = logging.handlers.TimedRotatingFileHandler(logfile, 'midnight')
	formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
	hdlr.setFormatter(formatter)
	suLogger.addHandler(hdlr)
	suLogger.setLevel(10)
	return suLogger

def createExploitLogFile():
	### create exploit logfile
	logfile = "logs/exploits.log"
	exLogger = logging.getLogger("amun-ex")
	#hdlr = logging.FileHandler(logfile)
	hdlr = logging.handlers.TimedRotatingFileHandler(logfile, 'midnight')
	formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
	hdlr.setFormatter(formatter)
	exLogger.addHandler(hdlr)
	exLogger.setLevel(10)
	return exLogger

def createSubmitLogFile():
	### create submit logfile
	logfile = "logs/submissions.log"
	smLogger = logging.getLogger("amun-sm")
	#hdlr = logging.FileHandler(logfile)
	hdlr = logging.handlers.TimedRotatingFileHandler(logfile, 'midnight')
	formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
	hdlr.setFormatter(formatter)
	smLogger.addHandler(hdlr)
	smLogger.setLevel(10)
	return smLogger


def createLoggingLogFile():
	### create log logfile
	logfile = "logs/logging.log"
	loLogger = logging.getLogger("amun-lo")
	#hdlr = logging.FileHandler(logfile)
	hdlr = logging.handlers.TimedRotatingFileHandler(logfile, 'midnight')
	formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
	hdlr.setFormatter(formatter)
	loLogger.addHandler(hdlr)
	loLogger.setLevel(10)
	return loLogger

def createAmunServerLogFile():
	### create amun server logfile
	logfile = "logs/amun_server.log"
	asLogger = logging.getLogger("amun-as")
	#hdlr = logging.FileHandler(logfile)
	hdlr = logging.handlers.TimedRotatingFileHandler(logfile, 'midnight')
	formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
	hdlr.setFormatter(formatter)
	asLogger.addHandler(hdlr)
	asLogger.setLevel(10)
	return asLogger

def createVulnLogFile():
	### create vulnerabilities logfile
	logfile = "logs/vulnerabilities.log"
	vuLogger = logging.getLogger("amun-vu")
	#hdlr = logging.FileHandler(logfile)
	hdlr = logging.handlers.TimedRotatingFileHandler(logfile, 'midnight')
	formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
	hdlr.setFormatter(formatter)
	vuLogger.addHandler(hdlr)
	vuLogger.setLevel(10)
	return vuLogger

def createShellcodeLogFile():
	### create shellcode manager logfile
	logfile = "logs/shellcode_manager.log"
	shLogger = logging.getLogger("amun-sh")
	#hdlr = logging.FileHandler(logfile)
	hdlr = logging.handlers.TimedRotatingFileHandler(logfile, 'midnight')
	formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
	hdlr.setFormatter(formatter)
	shLogger.addHandler(hdlr)
	shLogger.setLevel(10)
	return shLogger

def createRequestHandlerLogFile():
	### create amun request handler logfile
	logfile = "logs/amun_request_handler.log"
	arLogger = logging.getLogger("amun-ar")
	#hdlr = logging.FileHandler(logfile)
	hdlr = logging.handlers.TimedRotatingFileHandler(logfile, 'midnight')
	formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
	hdlr.setFormatter(formatter)
	arLogger.addHandler(hdlr)
	arLogger.setLevel(10)
	return arLogger

def createDownloadLogFile():
	### create download logfile
	logfile = "logs/download.log"
	dlLogger = logging.getLogger("amun-dl")
	#hdlr = logging.FileHandler(logfile)
	hdlr = logging.handlers.TimedRotatingFileHandler(logfile, 'midnight')
	formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
	hdlr.setFormatter(formatter)
	dlLogger.addHandler(hdlr)
	dlLogger.setLevel(10)
	return dlLogger

def createShellemuLogFile():
	### create shellemulation logfile
	logfile = "logs/shellemulator.log"
	emuLogger = logging.getLogger("amun-emu")
	#hdlr = logging.FileHandler(logfile)
	hdlr = logging.handlers.TimedRotatingFileHandler(logfile, 'midnight')
	formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
	hdlr.setFormatter(formatter)
	emuLogger.addHandler(hdlr)
	emuLogger.setLevel(10)
	return emuLogger

def createAnalysisLogFile():
	### create analysis logfile
	logfile = "logs/analysis.log"
	alLogger = logging.getLogger("amun-al")
	#hdlr = logging.FileHandler(logfile)
	hdlr = logging.handlers.TimedRotatingFileHandler(logfile, 'midnight')
	formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
	hdlr.setFormatter(formatter)
	alLogger.addHandler(hdlr)
	alLogger.setLevel(10)
	return alLogger

def runMain():
	### check for garbage collector
	if not gc.isenabled():
		log("activating garbage collector", 0, "info", None, True)
		gc.enable()
	### read configuration file
	conffile = "conf/amun.conf"
	config = amun_config_parser.AmunConfigParser(conffile)
	ipUtil = utils.utilities()
	amunServerIPEntry = config.getSingleValue("ip")
	amunServerIPList = ipUtil.genIPList(amunServerIPEntry)

	newUser = config.getSingleValue("user")
	newGroup = config.getSingleValue("group")

	connection_timeout = int(config.getSingleValue("connection_timeout"))
	bindport_timeout = int(config.getSingleValue("bindport_timeout"))
	ftp_timeout = int(config.getSingleValue("ftp_timeout"))
	tftp_retransmissions = int(config.getSingleValue("tftp_retransmissions"))
	tftp_max_retransmissions = int(config.getSingleValue("tftp_max_retransmissions"))

	refused_blocktime = int(config.getSingleValue("refused_blocktime"))
	timeout_blocktime = int(config.getSingleValue("timeout_blocktime"))
	sucdown_blocktime = int(config.getSingleValue("sucdown_blocktime"))
	sucexpl_blocktime = int(config.getSingleValue("sucexpl_blocktime"))

	block_refused = int(config.getSingleValue("block_refused"))
	block_timeout = int(config.getSingleValue("block_timeout"))
	block_sucdown = int(config.getSingleValue("block_sucdown"))
	block_sucexpl = int(config.getSingleValue("block_sucexpl"))

	store_unfinished_tftp = int(config.getSingleValue("store_unfinished_tftp"))
	check_http_filesize = int(config.getSingleValue("check_http_filesize"))
	replace_locals = int(config.getSingleValue("replace_local_ip"))
	allow_ping = int(config.getSingleValue("honeypot_pingable"))
	check_new_vulns = int(config.getSingleValue("check_new_vulns"))

	log_local_downloads = int(config.getSingleValue("log_local_downloads"))
	verbose_logging = int(config.getSingleValue("verbose_logging"))
	ftp_port_range = config.getSingleValue("ftp_port_range")
	ftp_nat_ip = config.getSingleValue("ftp_nat_ip")

	if ftp_nat_ip!="None":
		ipReg = re.compile("(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
		match = ipReg.search(ftp_nat_ip)
		if not match:
			ftp_nat_ip = socket.gethostbyaddr(ftp_nat_ip)[2][0]

	if not allow_ping:
		### set iptables rule to block ping
		ipt_command = "INPUT -p icmp -j DROP"
		command = "iptables -A %s" % (ipt_command)
		child = subprocess.Popen([command], shell=True, bufsize=1024, stdout=subprocess.PIPE, close_fds=True)
		child.wait()
	log("all servers listening on: %s" % (amunServerIPEntry), 0, "info", None, True)
	vuln_modules = readVulnModules(config)
	submit_modules = readSubmitModules(config)
	log_modules = readLogModules(config)
	### create download logfile
	dlLogger = createDownloadLogFile()
	### create unknown download logfile
	ukLogger = createUnknownDownloadLogFile()
	### create successfull download logfile
	suLogger = createSucDownloadLogFile()
	### create exploit logfile
	exLogger = createExploitLogFile()
	### create amun server logfile
	asLogger = createAmunServerLogFile()
	### create amun request handler logfile
	arLogger = createRequestHandlerLogFile()
	### create shellcode manager logfile
	shLogger = createShellcodeLogFile()
	### create vulnerabilities logfile
	vuLogger = createVulnLogFile()
	### create submission logfile
	smLogger = createSubmitLogFile()
	### create logging logfile
	loLogger = createLoggingLogFile()
	### create shellemulator logfile
	emuLogger = createShellemuLogFile()
	### create Socket and Download Dicts
	currentSockets = {}
	currentDownloads = {}
	tftp_downloads = {}
	ftp_downloads = {}
	bindports = {}
	### Event Dictionary
	event_dict = {}
	event_dict['download'] = {}
	event_dict['exploit'] = {}
	event_dict['successfull_downloads'] = {}
	event_dict['refused_connections'] = {}
	event_dict['timeout_connections'] = {}
	event_dict['sucdown_connections'] = {}
	event_dict['sucexpl_connections'] = {}
	event_dict['initial_connections'] = {}
	### configuration Dictionary
	config_dict = {}
	config_dict['block_refused'] = block_refused
	config_dict['block_timeout'] = block_timeout
	config_dict['block_sucdown'] = block_sucdown
	config_dict['block_sucexpl'] = block_sucexpl
	config_dict['replace_locals'] = replace_locals
	config_dict['store_unfinished_tftp'] = store_unfinished_tftp
	config_dict['check_http_filesize'] = check_http_filesize
	config_dict['tftp_max_retransmissions'] = tftp_max_retransmissions
	config_dict['check_new_vulns'] = check_new_vulns
	config_dict['log_local_downloads'] = log_local_downloads
	config_dict['ftp_port_range'] = ftp_port_range
	config_dict['ftp_nat_ip'] = ftp_nat_ip
	config_dict['last_check'] = int(time.time())
	config_dict['verbose_logging'] = int(verbose_logging)
	del block_refused
	del block_timeout
	del block_sucexpl
	del replace_locals
	del store_unfinished_tftp
	del check_http_filesize
	del tftp_max_retransmissions
	del check_new_vulns
	del log_local_downloads
	del ftp_port_range
	del ftp_nat_ip
	del verbose_logging
	### Logger Dictionary
	divLogger = {}
	divLogger['download'] = dlLogger
	divLogger['unknownDownload'] = ukLogger
	divLogger['amunServer'] = asLogger
	divLogger['requestHandler'] = arLogger
	divLogger['shellcode'] = shLogger
	divLogger['vulnerability'] = vuLogger
	divLogger['shellemulator'] = emuLogger
	del dlLogger
	del ukLogger
	del asLogger
	del arLogger
	del shLogger
	del vuLogger
	del emuLogger
	### Register Shellcode Decoders
	regDecode = decoders.decoders()
	decodersDict = regDecode.getDecoders()
	del regDecode
	portList = []
	vuln_ports = vuln_modules.keys()
	#for vport in vuln_ports:
	#	portList.append(int(vport))
	portList = map(int, vuln_ports)
	running = True
	portList.sort()
	### server liste
	serverList = {}
	### create TCP servers
	for port in portList:
		for amun_server_ip in amunServerIPList:
			server = amunServer((amun_server_ip,port), "tcp", currentSockets, decodersDict, event_dict, vuln_modules, divLogger, config_dict)
			serverList[port] = server
			del server
	del portList
	del vuln_ports
	### windows messenger popup spam
	#server = amunServer((amun_server_ip,1026), "udp", currentSockets, decodersDict, event_dict, vuln_modules, divLogger, config_dict)
	#for amun_server_ip in amunServerIPList:
		### add UDP Server for Remote Buffer Overflow in sipXtapi
		#server = amunServer((amun_server_ip,5060), "udp", currentSockets, decodersDict, event_dict, vuln_modules, divLogger, config_dict)
		### and another one
		#server = amunServer((amun_server_ip,5061), "udp", currentSockets, decodersDict, event_dict, vuln_modules, divLogger, config_dict)
		### check port 7100 udp
		#server = amunServer((amun_server_ip,7100), "udp", currentSockets, decodersDict, event_dict, vuln_modules, divLogger, config_dict)
		#del server
	### fifo queue of last stored binaries to reduce IO
	lastBinaries = utils.fifoqueue(10)
	### Lower Priviliges
	if newUser!="root" and newGroup!="root":
		lowerPrivileges(newUser, newGroup)
	log("ready for evil orders:", 0, "info", None, True)
	while running:
		try:
			### loop over open sockets
			asyncore.loop(timeout=1, use_poll=True, count=1)
			### check idle connections
			check_idle_connections(currentSockets, connection_timeout, event_dict, divLogger['amunServer'], config_dict)
			### check download events
			check_download_events(event_dict, config_dict, currentDownloads, bindports, tftp_downloads, divLogger, currentSockets, ftp_downloads, decodersDict)
			### check exploit events
			check_for_exploit_event(event_dict, exLogger, log_modules, loLogger)
			### check successfull downloads
			check_for_succ_download_event(event_dict, suLogger, submit_modules, smLogger, config_dict['block_sucdown'], lastBinaries, log_modules, loLogger)
			### check initial connection
			check_for_initial_connection_event(event_dict, exLogger, log_modules, loLogger, currentSockets, divLogger['amunServer'], config_dict['verbose_logging'])
			### check for idle bindports
			check_idle_bindports(bindports, bindport_timeout)
			### check for idle tftp downloads
			check_idle_tftp_downloads(tftp_downloads, tftp_retransmissions)
			### check for idle ftp downloads
			check_idle_ftp_downloads(ftp_downloads, ftp_timeout)
			### check the list of refused IPs
			check_refused_ips(event_dict, refused_blocktime, divLogger['amunServer'], config_dict['verbose_logging'])
			### check the list of timeouted IPs
			check_timeout_ips(event_dict, timeout_blocktime, divLogger['amunServer'], config_dict['verbose_logging'])
			### check the list of successfull download IPs
			check_sucdown_ips(event_dict, sucdown_blocktime, divLogger['amunServer'], config_dict['verbose_logging'])
			### check the list of successfull exploit IPs
			check_sucexpl_ips(event_dict, sucexpl_blocktime, divLogger['amunServer'], config_dict['verbose_logging'])
			### check running TCP Servers and reload config
			(serverList, vuln_modules, refused_blocktime, connection_timeout, bindport_timeout, ftp_timeout, tftp_retransmissions, timeout_blocktime, sucdown_blocktime, sucexpl_blocktime) = checkServers(serverList, vuln_modules, divLogger, amunServerIPList, currentSockets, decodersDict, event_dict, config_dict, config, refused_blocktime, connection_timeout, bindport_timeout, ftp_timeout, tftp_retransmissions, timeout_blocktime, sucdown_blocktime, sucexpl_blocktime)
			### release CPU for short time
			time.sleep(.0001)
		except socket.error, e:
			pass
		except StandardError, e:
			print "amun_server main loop standard error"
			print "error: %s" % (e)
			f = StringIO.StringIO()
			traceback.print_exc(file=f)
			print f.getvalue()
			running = False
			break
		except KeyboardInterrupt:
			running = False
			break
	log("close all servers", 0, "info", None, True)
	if len(serverList)>0:
		server_keys = serverList.keys()
		for key in server_keys:
			serverList[key].close()
	log("close remaining bindports", 0, "info", None, True)
	if len(bindports)>0:
		check_idle_bindports(bindports, 0)
	log("close remaining sockets", 0, "info", None, True)
	if len(currentSockets)>0:
		conn_keys = currentSockets.keys()
		for key in conn_keys:
			try:
				currentSockets[key][1].shutdown(socket.SHUT_RDWR)
			except socket.error, e:
				if currentSockets.has_key(key):
					del currentSockets[key]
	### Empty IPTables Input Table
	if not allow_ping:
		command = "iptables -D %s" % (ipt_command)
		child = subprocess.Popen([command], shell=True, bufsize=1024, stdout=subprocess.PIPE, close_fds=True)
		child.wait()
		log("flushing iptables", 0, "info", None, True)
	asyncore.close_all()
	log("quit", 0, "crit", None, True)

def lowerPrivileges(uidName="nobody", gidGroup="nogroup"):
	""" drop root privileges """
	import pwd
	import grp

	startUID = os.getuid()
	startGID = os.getgid()
	startUIDname = pwd.getpwuid(startUID)[0]
	startGIDname = grp.getgrgid(startGID)[0]
	log("started as %s/%s" % (startUIDname, startGIDname), 0, "info", None, True)

	### if not started as root ignore
	if startUID != 0:
		log("not started as root, ignoring privilege dropping", 0, "info", None, True)
		return

	runAsUID = pwd.getpwnam(uidName)[2]
	runAsGID = grp.getgrnam(gidGroup)[2]

	try:
		os.setgid(runAsGID)
	except OSError, e:
		log("could not set new group %s" % (e), 0, "info", None, True)

	try:
		os.setuid(runAsUID)
	except OSError, e:
		log("could not set new user %s" % (e), 0, "info", None, True)

	newUMask = 077
	oldUMask = os.umask(newUMask)
	log("changing umask from %s to %s" % (oct(oldUMask), oct(newUMask)), 0, "info", None, True)

	resUID = pwd.getpwuid(os.getuid())[0]
	resGID = grp.getgrgid(os.getgid())[0]
	log("now running as %s/%s" % (resUID,resGID), 0, "info", None, True)
	return

def readOptions():
	""" read commandline options """

	usage = """
        %prog [options]
        """
	parser = optparse.OptionParser(usage=usage, version = "%prog v"+__version__)

	parser.add_option("-a", "--analyse",
			action="store", type="string", dest="filename", default=None,
			help="analyse given file for known shellcode")

	parser.add_option("-s", "--shellcmd",
			action="store_true", dest="shellcmd", default=False,
			help="contains plain shellcommands in combination with --analyse (-a)")

	return parser.parse_args()


def runAnalysis(filename, shellcmd):
	import shellcode_mgr_core
	import os
	try:
		if os.path.exists(filename):
			config_dict = {}
			config_dict['verbose_logging'] = 1
			regDecode = decoders.decoders()
			decodersDict = regDecode.getDecoders()
			log("run analysis on file %s" % (filename), 0, "info", None, True)
			fp = open(filename, 'r')
			file_content = "".join(fp.readlines())
			fp.close()
			log("done reading file ... starting analysis", 0, "info", None, True)
			alLogger = createAnalysisLogFile()
			shellcode_manager = shellcode_mgr_core.shell_mgr(decodersDict, alLogger, config_dict)
			shellcodeSet = {}
			shellcodeSet['vulnname'] = "FileCheck"
			shellcodeSet['shellcode'] = file_content
			if shellcmd:
				result = shellcode_manager.start_shellcommand_matching(shellcodeSet, "127.0.0.1", "127.0.0.1", "0", 0, True)
			else:
				result = shellcode_manager.start_matching(shellcodeSet, "127.0.0.1", "127.0.0.1", "0", 0, True)
			print result
		else:
			log("no such file %s" % (filename), 0, "crit", None, True)
	except KeyboardInterrupt:
		sys.exit(1)


if __name__ == '__main__':
	workdir = sys.path[0]
	os.chdir(workdir)

	sys.path.append("core")
	sys.path.append("shellcodes")

	import decoders
	import amun_request_handler
	import amun_logging
	import amun_config_parser
	import download_core
	import tftp_download_core
	import ftp_download_core
	import bindport_core
	import shellcode_mgr_core
	import utils

	(opts, args) = readOptions()
	art = """
    _____
   /  _  \   _____  __ __  ____
  /  /_\  \ /     \|  |  \/    \\
 /    |    \  Y Y  \  |  /   |  \\
 \____|__  /__|_|  /____/|___|  /
         \/      \/           \/
"""
	mess = "starting Amun server..."
	print "\n%s\n\t\t%s\n" % (art, mess)
	if not opts.filename:
		runMain()
	elif opts.filename:
		runAnalysis(opts.filename, opts.shellcmd)
	else:
		print "something is wrong"
