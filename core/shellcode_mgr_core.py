"""
[Amun - low interaction honeypot]
Copyright (C) [2008]  [Jan Goebel]

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, see <http://www.gnu.org/licenses/>
"""

try:
	import psyco ; psyco.full()
	from psyco.classes import *
except ImportError:
	pass

import re
import urlparse
import hashlib
import os
import socket
import struct
import base64

import sys
import StringIO
import traceback

import iprange
import amun_logging

import sets

class shell_mgr:
	def __init__(self, decodersDict, shLogger, config_dict):
		### configuration stuff
		self.config_dict = config_dict
		### create local network ranges
		self.localIPliste = []
		self.localIPliste.append( iprange.IPRange("0.0.0.0/8") )
		self.localIPliste.append( iprange.IPRange("10.0.0.0/8") )
		self.localIPliste.append( iprange.IPRange("127.0.0.0/8") )
		self.localIPliste.append( iprange.IPRange("169.254.0.0/16") )
		self.localIPliste.append( iprange.IPRange("172.16.0.0/12") )
		self.localIPliste.append( iprange.IPRange("192.168.0.0/16") )
		### logging
		self.log_obj = amun_logging.amun_logging("shellcode_manager", shLogger)
		### compile the regex
		### check IP
		self.checkIPExpre = decodersDict['checkIP']
		### match URLs (http|https|ftp)
		self.urlExpre = decodersDict['url']
		self.tftpExpre1 = decodersDict['tftp1']
		self.tftpExpre = decodersDict['tftp']
		self.ftpcmdExpre = decodersDict['ftpcmd']
		self.ftpcmd2Expre = decodersDict['ftpcmd2']
		
		self.ftpcmd3IPExpre = decodersDict['ftpcmd3ip']
		self.ftpcmd3UserPassExpre = decodersDict['ftpcmd3userpass']
		self.ftpcmd3BinExpre = decodersDict['ftpcmd3binary']

		### Match different Shellcodes
		self.rothenburg = decodersDict['rothenburg']
		self.rothenburg_bindport = decodersDict['rothenburg_bindport']
		self.rothenburg_bindport2 = decodersDict['rothenburg_bindport2']
		self.schoenborn_connback = decodersDict['schoenborn_connback']

		self.adenau  = decodersDict['adenau']
		self.adenau_bindport = decodersDict['adenau_bindport']
		
		self.heidelberg = decodersDict['heidelberg']

		self.mainz = decodersDict['mainz']
		self.mainz_bindport1 = decodersDict['mainz_bindport1']
		self.mainz_bindport2 = decodersDict['mainz_bindport2']
		self.mainz_connback1 = decodersDict['mainz_connback1']
		self.mainz_connback2 = decodersDict['mainz_connback2']
		self.mainz_connback3 = decodersDict['mainz_connback3']

		self.wuerzburg = decodersDict['wuerzburg']
		self.wuerzburg_file = decodersDict['wuerzburg_file']

		self.aachen = decodersDict['aachen']
		self.aachen_connback = decodersDict['aachen_connback']

		self.schauenburg = decodersDict['schauenburg']
		self.schauenburg_bindport = decodersDict['schauenburg_bindport']
		self.schauenburg_connback = decodersDict['schauenburg_connback']

		self.koeln = decodersDict['koeln']
		self.koeln_bindport = decodersDict['koeln_bindport']

		self.lichtenfels = decodersDict['lichtenfels']
		self.lichtenfels_connback = decodersDict['lichtenfels_connback']

		self.leimbach = decodersDict['leimbach']
		self.berlin = decodersDict['berlin']

		self.linkbot = decodersDict['linkbot']
		self.linkbot_connback = decodersDict['linkbot_connback']
		self.linkbot_connback2 = decodersDict['linkbot_connback2']
		self.linkbot_connback3 = decodersDict['linkbot_connback3']

		self.furth = decodersDict['furth']

		self.pexalphanum = decodersDict['pexalphanum']
		self.pexalphanum_bindport = decodersDict['pexalphanum_bindport']

		self.alphaNum = decodersDict['alphaNum']
		self.alphaNum2 = decodersDict['alphaNum2']

		self.mannheim = decodersDict['mannheim']

		self.duesseldorf = decodersDict['duesseldorf']

		self.langenfeld = decodersDict['langenfeld']
		self.langenfeld_connback = decodersDict['langenfeld_connback']
		self.langenfeld_connback2 = decodersDict['langenfeld_connback2']

		self.bonn = decodersDict['bonn']

		self.siegburg = decodersDict['siegburg']
		self.siegburg_bindshell = decodersDict['siegburg_bindshell']
		
		self.ulm = decodersDict['ulm']
		self.ulm_bindshell = decodersDict['ulm_bindshell']
		self.ulm_connback = decodersDict['ulm_connback']

		self.bergheim = decodersDict['bergheim']
		self.bergheim_connback = decodersDict['bergheim_connback']

		self.alpha2endchar = decodersDict['alpha2endchar']
		self.alpha2connback = decodersDict['alpha2connback']
		self.alpha2bind = decodersDict['alpha2bind']

		### unnamed shellcode
		self.bind1 = decodersDict['bindshell1']
		self.bind2 = decodersDict['bindshell2']
		self.bind3 = decodersDict['bindshell3']
		self.bind4 = decodersDict['bindshell4']
		self.plain1 = decodersDict['plain1']
		self.plain2 = decodersDict['plain2']

	def start_matching(self, vulnResult, attIP, ownIP, ownPort, replace_locals=0, displayShellCode=False):
		try:
			self.shellcode = str(vulnResult['shellcode']).replace('\0','').strip()
			self.shellcode2 = str(vulnResult['shellcode']).strip()
			#self.shellcode = vulnResult['shellcode']
			self.attIP = attIP
			self.ownIP = ownIP
			self.replace_locals = replace_locals
			self.displayShellCode = displayShellCode
			self.resultSet = {}
			self.resultSet['vulnname'] = vulnResult['vulnname']
			self.resultSet['result'] = False
			self.resultSet['hostile_host'] = self.attIP
			self.resultSet['own_host'] = self.ownIP
			self.resultSet['found'] = "None"
			self.resultSet['path'] = "None"
			self.resultSet['host'] = "None"
			self.resultSet['port'] = "None"
			self.resultSet['xorkey'] = "None"
			self.resultSet['username'] = "None"
			self.resultSet['passwort'] = "None"
			self.resultSet['dlident'] = "None"
			self.resultSet['displayURL'] = "None"
			self.resultSet['isLocalIP'] = False
			self.resultSet['shellcodeName'] = "None"
			### erst http url checken
			http_result = self.match_url("None")
			if http_result==1 and self.resultSet['result']:
				return self.resultSet
			### url matched but incomplete
			if http_result==2:
				return self.resultSet
			### shellcodes matchen
			if self.match_shellcodes() and self.resultSet['result']:
				return self.resultSet
			### plain FTP matchen
			if self.match_plainFTP() and self.resultSet['result']:
				return self.resultSet
			### no match than write hexdump
			self.write_hexdump(self.shellcode, vulnResult['vulnname'].replace('Vulnerability','',1), ownPort)
			self.write_hexdump(self.shellcode2, vulnResult['vulnname'].replace('Vulnerability','',1), "raw-"+str(ownPort))
			return self.resultSet
		except KeyboardInterrupt:
			raise

	def start_shellcommand_matching(self, vulnResult, attIP, ownIP, ownPort, replace_locals, displayShellCode):
		try:
			self.shellcode = str(vulnResult['shellcode']).strip()
			self.attIP = attIP
			self.ownIP = ownIP
			self.replace_locals = replace_locals
			self.displayShellCode = displayShellCode
			self.resultSet = {}
			self.resultSet['vulnname'] = vulnResult['vulnname']
			self.resultSet['result'] = False
			self.resultSet['hostile_host'] = self.attIP
			self.resultSet['own_host'] = self.ownIP
			self.resultSet['found'] = "None"
			self.resultSet['path'] = "None"
			self.resultSet['host'] = "None"
			self.resultSet['port'] = "None"
			self.resultSet['xorkey'] = "None"
			self.resultSet['username'] = "None"
			self.resultSet['passwort'] = "None"
			self.resultSet['dlident'] = "None"
			self.resultSet['displayURL'] = "None"
			self.resultSet['isLocalIP'] = False
			self.resultSet['shellcodeName'] = "None"
			### erst http url checken
			http_result = self.match_url("None")
			if http_result==1 and self.resultSet['result']:
				return self.resultSet
			### url matched but incomplete
			if http_result==2:
				return self.resultSet
			### plain FTP matchen
			if self.match_plainFTP() and self.resultSet['result']:
				return self.resultSet
			### plain TFTP matchen
			if self.match_plainTFTP() and self.resultSet['result']:
				return self.resultSet
			### old plain FTP matchen
			#if self.macht_FTPold() and self.resultSet['result']:
			#	return self.resultSet
			### no match than write hexdump
			self.write_hexdump(self.shellcode, vulnResult['vulnname'].replace('Vulnerability','',1), ownPort)
			return self.resultSet
		except KeyboardInterrupt:
			raise

	def decXorHelper(self, char, key):
		unpack = struct.unpack
		pack = struct.pack
		return pack('B', unpack('B',char)[0] ^ key )

	def decrypt_xor(self, key, data):
		unpack = struct.unpack
		pack = struct.pack
		return "".join([self.decXorHelper(char,key) for char in data])

	def decrypt_multi_xor(self, keys, data, position=0):
		unpack = struct.unpack
		pack = struct.pack
		decrypted = []
		keyPos = position % len(keys)
		for char in data:
			decrypted.append(pack('B', unpack('B',char)[0] ^ keys[keyPos]  ))
			keyPos = (keyPos + 1) % len(keys)
		return "".join(decrypted)

	def checkFTP(self, cmd):
		if cmd.startswith('cmd /c echo open'):
			cmd_liste = cmd.split(' ')
			target_ip = cmd_liste[4]
			#if self.replace_locals:
			match = self.checkIPExpre.search(target_ip)
			if match:
				local = self.check_local(target_ip)
				if local and self.replace_locals:
					target_ip = self.attIP
				elif local and not self.replace_locals:
					self.resultSet['isLocalIP'] = True
					self.log_obj.log("local IP found" , 6, "crit", True, True)
			else:
				self.log_obj.log("no IP: %s" % (ip) , 6, "crit", True, True)
			self.resultSet['host'] = target_ip
			self.resultSet['port'] = int(cmd_liste[5]) % 65551
			if cmd_liste[8]=="user":
				self.resultSet['username'] = cmd_liste[9]
				self.resultSet['passwort'] = cmd_liste[10]
			if cmd_liste[14]=="get":
				self.resultSet['path'] = [cmd_liste[15]]
			self.resultSet['dlident'] = "%s%i%s" % (target_ip.replace('.',''), self.resultSet['port'], cmd_liste[15].replace('/',''))
			ftpURL = "ftp://%s:%s@%s:%s%s" % (self.resultSet['username'], self.resultSet['passwort'], self.resultSet['host'], self.resultSet['port'], self.resultSet['path'])
			self.resultSet['displayURL'] = ftpURL
			self.resultSet['shellcodeName'] = "plainftp"
			return True
		return False

	def match_shellcodes(self):
		try:
			### Match Wuerzburg Shellcode
			if self.displayShellCode:
				print "starting Wuerzburg matching ..."
				sys.stdout.flush()
			match = self.wuerzburg.search( self.shellcode )
			if match:
				#self.write_hexdump(self.shellcode, "wuerzburg")
				raw_port = match.groups()[0]
				port = struct.unpack('!H',raw_port)[0]
				raw_ip = match.groups()[1]
				ip = struct.unpack('I',raw_ip)[0]
				ip = struct.pack('I',ip^0xaaaaaaaa)
				ip = socket.inet_ntoa(ip)
				key = struct.unpack('B',match.groups()[2])[0]
				if self.replace_locals and self.check_local(ip):
					ip = self.attIP
				elif self.check_local(ip):
					self.resultSet['isLocalIP'] = True
				self.log_obj.log("found wuerzburg shellcode (key: %s port: %s ip: %s)" % (key, port, ip), 9, "info", False, True)
				self.resultSet['dlident'] = "%s%s" % (ip.replace('.',''), port)
				self.resultSet['result'] = True
				self.resultSet['host'] = ip
				self.resultSet['port'] = port
				self.resultSet['found'] = "connectbackfiletrans"
				filename = self.handle_wuerzburg(key)
				connbackURL = "cbackf://%s:%s/%s" % (ip, port, filename)
				self.resultSet['displayURL'] = connbackURL
				self.resultSet['shellcodeName'] = "wuerzburg"
				return True
			### Match Leimbach shellcode
			if self.displayShellCode:
				print "starting Leimbach matching ..."
				sys.stdout.flush()
			match = self.leimbach.search( self.shellcode )
			if match:
				key = struct.unpack('B',match.groups()[0])[0]
				self.resultSet['xorkey'] = key
				self.log_obj.log("found leimbach xor decoder (key: %s)" % (key), 9, "info", False, True)
				dec_shellcode = self.decrypt_xor(key, self.shellcode)
				if self.handle_leimbach( key, dec_shellcode ):
					return True
			### Match Adenau Shellcode
			if self.displayShellCode:
				print "starting Adenau matching ..."
				sys.stdout.flush()
			match = self.adenau.search( self.shellcode )
			if match:
				#self.write_hexdump(self.shellcode, "adenau")
				keys = {}
				for i in xrange(0,4):
					keys[i] =  struct.unpack('B',match.groups()[i])[0]
				self.resultSet['xorkey'] = keys
				self.log_obj.log("found adenau xor decoder (keys: %s)" % (keys), 9, "info", False, True)
				if self.handle_adenau( keys ):
					return True
			### Match Mannheim Shellcode1
			if self.displayShellCode:
				print "starting Mannheim matching ..."
				sys.stdout.flush()
			match = self.mannheim.search( self.shellcode )
			if match:
				#self.write_hexdump(self.shellcode, "mannheim")
				key = struct.unpack('B',match.groups()[0])[0]
				self.log_obj.log("found shell1 (key: %s)" % (key), 9, "info", True, True)
				enc_command = match.groups()[1]
				dec_command = self.decrypt_xor(key,enc_command)
				if self.checkFTP(dec_command):
					self.log_obj.log("command found: %s" % (dec_command), 9, "info", True, True)
					self.resultSet['result'] = True
					self.resultSet['xorkey'] = key
					self.resultSet['found'] = "ftp"
					self.resultSet['shellcodeName'] = "mannheim"
					return True
			### Match Unnamed Shellcode2
			if self.displayShellCode:
				print "starting Unnamed Shellcode2 matching ..."
				sys.stdout.flush()
			match = self.plain2.search( self.shellcode )
			if match:
				raw_port = match.groups()[0]
				port = struct.unpack('!H',raw_port)[0]
				self.log_obj.log("found shell2 (port: %s)" % (port), 9, "info", True, True)
				self.resultSet['port'] = port
				self.resultSet['found'] = "bindport"
				self.resultSet['result'] = True
				bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
				self.resultSet['dlident'] = bindportID
				bindURL = "bind://%s:%s/" % (self.ownIP, port)
				self.resultSet['displayURL'] = bindURL
				self.resultSet['shellcodeName'] = "unnamedshell2"
				return True
			### Match Aachen Shellcode (aka zuc_winshit)
			if self.displayShellCode:
				print "starting Aachen Shellcode matching ..."
				sys.stdout.flush()
			match = self.aachen.search( self.shellcode )
			if match:
				#self.write_hexdump(self.shellcode, "aachen")
				ipkey = struct.unpack('!L',match.groups()[0])[0]
				portkey = struct.unpack('!H',match.groups()[1])[0]
				self.log_obj.log("found aachen shellcode (ipkey: %s portkey: %s)" % (ipkey, portkey), 9, "info", False, True)
				if self.handle_aachen( ipkey, portkey ):
					return True
			### Match Mainz / Bielefeld Shellcode
			if self.displayShellCode:
				print "starting Mainz / Bielefeld matching ..."
				sys.stdout.flush()
			match = self.mainz.search( self.shellcode )
			if match:
				#self.write_hexdump(self.shellcode, "mainz")
				key = struct.unpack('B',match.groups()[0])[0]
				self.resultSet['xorkey'] = key
				self.log_obj.log("found mainz/bielefeld xor decoder (key: %s)" % (key), 9, "info", False, True)
				dec_shellcode = self.decrypt_xor(key, self.shellcode)
				if self.handle_bielefeld(key, dec_shellcode):
					return True
			### Match Heidelberg Shellcode
			if self.displayShellCode:
				print "starting Heidelberg matching ..."
				sys.stdout.flush()
			match = self.heidelberg.search( self.shellcode )
			if match:
				#self.write_hexdump(self.shellcode, "mainz2")
				key = struct.unpack('B',match.groups()[0])[0]
				self.resultSet['xorkey'] = key
				self.log_obj.log("found heidelberg xor decoder (key: %s)" % (key), 9, "info", False, True)
				dec_shellcode = self.decrypt_xor(key, self.shellcode)
				self.write_hexdump(dec_shellcode, "heidelberg")
				if self.handle_heidelberg(key, dec_shellcode):
					return True
			### Match Rothenburg / Schoenborn Shellcode
			if self.displayShellCode:
				print "starting Rothenburg / Schoenborn matching ..."
				sys.stdout.flush()
			match = self.rothenburg.search( self.shellcode )
			if match:
				#self.write_hexdump(self.shellcode, "rothenburg")
				keys = {}
				for i in xrange(0,4):
					keys[i] =  struct.unpack('B',match.groups()[i])[0]
				self.resultSet['xorkey'] = keys
				self.log_obj.log("found rothenburg/schoenborn xor decoder (keys: %s)" % (keys), 9, "info", False, True)
				if self.handle_rothenburg( keys ):
					return True
			### Match Koeln Shellcode
			if self.displayShellCode:
				print "starting Koeln matching ..."
				sys.stdout.flush()
			match = self.koeln.search( self.shellcode )
			if match:
				keys = {}
				for i in xrange(0,4):
					keys[i] =  struct.unpack('B',match.groups()[i])[0]
				self.resultSet['xorkey'] = keys
				self.log_obj.log("found koeln xor decoder (keys: %s)" % (keys), 9, "info", False, True)
				if self.handle_koeln( keys ):
					return True
			### Match linkbot XOR shellcode (aka Lindau)
			if self.displayShellCode:
				print "starting Lindau matching ..."
				sys.stdout.flush()
			match = self.linkbot.search( self.shellcode )
			if match:
				#self.write_hexdump(self.shellcode, "lindau")
				key = struct.unpack('B',match.groups()[0])[0]
				self.resultSet['xorkey'] = key
				self.log_obj.log("found linkbot xor decoder (key: %s)" % (key), 9, "info", False, True)
				dec_shellcode = self.decrypt_xor(key, self.shellcode)
				if self.handle_linkbot( key, dec_shellcode ):
					return True
			### Match schauenburg XOR shellcode
			if self.displayShellCode:
				print "starting schauenburg matching ..."
				sys.stdout.flush()
			match = self.schauenburg.search( self.shellcode )
			if match:
				key = struct.unpack('B',match.groups()[0])[0]
				self.resultSet['xorkey'] = key
				self.log_obj.log("found schauenburg xor decoder (key: %s)" % (key), 9, "info", False, True)
				dec_shellcode = self.decrypt_xor(key, self.shellcode)
				if self.handle_schauenburg( key, dec_shellcode ):
					return True
			### Match plain1 shellcode
			if self.displayShellCode:
				print "starting plain1 matching ..."
				sys.stdout.flush()
			match = self.plain1.search( self.shellcode )
			if match:
				raw_port = match.groups()[0]
				port = struct.unpack('<H',raw_port)[0]
				self.log_obj.log("found plain1 shellcode (port: %s)" % (port), 9, "info", False, True)
				self.resultSet['port'] = port
				self.resultSet['found'] = "bindport"
				self.resultSet['result'] = True
				bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
				self.resultSet['dlident'] = bindportID
				bindURL = "bind://%s:%s/" % (self.ownIP, port)
				self.resultSet['displayURL'] = bindURL
				self.resultSet['shellcodeName'] = "plain1"
				return True
			### Match PexAlphaNumeric shellcode (mixedcase_w32sehgetpc)
			if self.displayShellCode:
				print "starting PexAlphaNumeric matching ..."
				sys.stdout.flush()
			match = self.pexalphanum.search( self.shellcode )
			if match:
				decoder = match.groups()[0]
				payload = match.groups()[1]
				self.log_obj.log("found PexAlphaNum shellcode", 9, "info", False, True)
				if self.handle_pexalphanum( decoder, payload ):
					return True

			### Match Lichtenfels shellcode
			if self.displayShellCode:
				print "starting Lichtenfels matching ..."
				sys.stdout.flush()
			match = self.lichtenfels.search( self.shellcode )
			if match:
				#self.write_hexdump(self.shellcode, "lichtenfels")
				key = struct.unpack('B',match.groups()[0])[0]
				self.resultSet['xorkey'] = key
				self.log_obj.log("found lichtenfels xor decoder (key: %s)" % (key), 9, "info", False, True)
				dec_shellcode = self.decrypt_xor(key, self.shellcode)
				if self.handle_lichtenfels( key, dec_shellcode ):
					return True
			### Match Berlin shellcode
			if self.displayShellCode:
				print "starting Berlin matching ..."
				sys.stdout.flush()
			match = self.berlin.search( self.shellcode )
			if match:
				key = struct.unpack('B',match.groups()[0])[0]
				self.resultSet['xorkey'] = key
				self.log_obj.log("found berlin xor decoder (key: %s)" % (key), 9, "info", False, True)
				dec_shellcode = self.decrypt_xor(key, self.shellcode)
				if self.handle_berlin( key, dec_shellcode ):
					return True
			### Match Furth shellcode
			if self.displayShellCode:
				print "starting Furth matching ..."
				sys.stdout.flush()
			match = self.furth.search( self.shellcode )
			if match:
				key = struct.unpack('B',match.groups()[0])[0]
				self.resultSet['xorkey'] = key
				self.log_obj.log("found furth xor decoder (key: %s)" % (key), 9, "info", False, True)
				dec_shellcode = self.decrypt_xor(key, self.shellcode)
				if self.match_url(dec_shellcode) == 1:
					return True
				if self.match_plainFTP(dec_shellcode):
					return True
			### Match Duesseldorf shellcode
			if self.displayShellCode:
				print "starting Duesseldorf matching ..."
				sys.stdout.flush()
			match = self.duesseldorf.search( self.shellcode )
			if match:
				key1 = struct.unpack('B',match.groups()[0])[0]
				key2 = struct.unpack('B',match.groups()[1])[0]
				self.log_obj.log("found duesseldorf xor decoder (key1: %s, key2: %s)" % (key1, key2), 9, "info", False, True)
				if key1 == key2:
					self.resultSet['xorkey'] = key1
					dec_shellcode = self.decrypt_xor(key1, self.shellcode)
					if self.match_url(dec_shellcode) == 1:
						return True
				self.log_obj.log("xor keys differ, aborting for manual analysis", 9, "info", True, True)
			### Match Siegburg shellcode
			if self.displayShellCode:
				print "starting Siegburg matching ..."
				sys.stdout.flush()
			match = self.siegburg.search( self.shellcode )
			if match:
				key = struct.unpack('B',match.groups()[0])[0]
				self.log_obj.log("found siegburg xor decoder (key: %s)" % (key), 9, "info", False, True)
				self.resultSet['xorkey'] = key
				dec_shellcode = self.decrypt_xor(key, self.shellcode)
				if self.handle_siegburg( key, dec_shellcode ):
					return True
			### Match Ulm shellcode
			if self.displayShellCode:
				print "starting Ulm matching ..."
				sys.stdout.flush()
			match = self.ulm.search( self.shellcode )
			if match:
				keys = {}
				for i in xrange(0,4):
					keys[i] =  struct.unpack('B',match.groups()[i])[0]
				self.resultSet['xorkey'] = keys
				self.log_obj.log("found ulm xor decoder (keys: %s)" % (keys), 9, "info", False, True)
				if self.handle_ulm( keys ):
					return True
			### Match Langenfeld shellcode
			if self.displayShellCode:
				print "starting Langenfeld matching ..."
				sys.stdout.flush()
			match = self.langenfeld.search( self.shellcode )
			if match:
				key = struct.unpack('B',match.groups()[0])[0]
				self.log_obj.log("found langenfeld xor decoder (key: %s)" % (key), 9, "info", False, True)
				self.resultSet['xorkey'] = key
				dec_shellcode = self.decrypt_xor(key, self.shellcode)
				if self.handle_langenfeld( key, dec_shellcode ):
					return True
			### Match Bonn shellcode
			if self.displayShellCode:
				print "starting Bonn matching ..."
				sys.stdout.flush()
			match = self.bonn.search( self.shellcode )
			if match:
				#self.write_hexdump(self.shellcode, "bonn")
				key = struct.unpack('B',match.groups()[0])[0]
				self.log_obj.log("found bonn xor decoder (key: %s)" % (key), 9, "info", False, True)
				self.resultSet['xorkey'] = key
				dec_shellcode = self.decrypt_xor(key, self.shellcode)
				if self.match_url(dec_shellcode) == 1:
					return True
			### Match Unnamed BindShellcode1
			if self.displayShellCode:
				print "starting Unnamed BindShellcode1 matching ..."
				sys.stdout.flush()
			match = self.bind1.search( self.shellcode )
			if match:
				raw_port = match.groups()[0]
				port = struct.unpack('!H',raw_port)[0]
				self.log_obj.log("found bindshell1 (port: %s)" % (port), 9, "info", True, True)
				self.resultSet['port'] = port
				self.resultSet['found'] = "bindport"
				self.resultSet['result'] = True
				bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
				self.resultSet['dlident'] = bindportID
				bindURL = "bind://%s:%s/" % (self.ownIP, port)
				self.resultSet['displayURL'] = bindURL
				self.resultSet['shellcodeName'] = "unnamedbind1"
				return True
			### Match Unnamed BindShellcode2
			if self.displayShellCode:
				print "starting Unnamed BindShellcode2 matching ..."
				sys.stdout.flush()
			match = self.bind2.search( self.shellcode )
			if match:
				raw_port = match.groups()[0]
				port = struct.unpack('!H',raw_port)[0]
				self.log_obj.log("found bindshell2 (port: %s)" % (port), 9, "info", True, True)
				self.resultSet['port'] = port
				self.resultSet['found'] = "bindport"
				self.resultSet['result'] = True
				bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
				self.resultSet['dlident'] = bindportID
				bindURL = "bind://%s:%s/" % (self.ownIP, port)
				self.resultSet['displayURL'] = bindURL
				self.resultSet['shellcodeName'] = "unnamedbind2"
				return True
			### Match Unnamed BindShellcode3
			if self.displayShellCode:
				print "starting Unnamed BindShellcode3 matching ..."
				sys.stdout.flush()
			match = self.bind3.search( self.shellcode2 )
			if match:
				raw_port = match.groups()[0]
				port = struct.unpack('!H',raw_port)[0]
				self.log_obj.log("found bindshell3 (port: %s)" % (port), 9, "info", True, True)
				self.resultSet['port'] = port
				self.resultSet['found'] = "bindport"
				self.resultSet['result'] = True
				bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
				self.resultSet['dlident'] = bindportID
				bindURL = "bind://%s:%s/" % (self.ownIP, port)
				self.resultSet['displayURL'] = bindURL
				self.resultSet['shellcodeName'] = "unnamedbind3"
				return True
			### Match Unnamed BindShellcode4
			if self.displayShellCode:
				print "starting Unnamed BindShellcode4 matching ..."
				sys.stdout.flush()
			match = self.bind4.search( self.shellcode )
			if match:
				raw_port = match.groups()[0]
				port = struct.unpack('!H',raw_port)[0]
				self.log_obj.log("found bindshell4 (port: %s)" % (port), 9, "info", True, True)
				self.resultSet['port'] = port
				self.resultSet['found'] = "bindport"
				self.resultSet['result'] = True
				bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
				self.resultSet['dlident'] = bindportID
				bindURL = "bind://%s:%s/" % (self.ownIP, port)
				self.resultSet['displayURL'] = bindURL
				self.resultSet['shellcodeName'] = "unnamedbind3"
				return True
			### Match Unnamed AlphaNumeric Shellcode
			if self.displayShellCode:
				print "starting Base64Encoded PexAlphaNumeric matching ..."
				sys.stdout.flush()
			match = self.alphaNum.search( self.shellcode )
			if match:
				payload = match.groups()[0]
				payload += "=="
				try:
					decodedPayload = base64.decodestring(payload)
					match = self.pexalphanum.search( decodedPayload )
					if match:
						decoder = match.groups()[0]
						payload = match.groups()[1]
						self.log_obj.log("found PexAlphaNum shellcode", 9, "info", False, True)
						if self.handle_pexalphanum( decoder, payload ):
							return True
				except:
					pass
			### Unnamed Plain URL Alpha
			if self.displayShellCode:
				print "starting Base64Encoded AlphaNumeric plain URL matching ..."
				sys.stdout.flush()
			match = self.alphaNum2.search( self.shellcode )
			if match:
				payload = match.groups()[0]
				payload += "=="
				try:
					decodedPayload = base64.decodestring(payload)
					http_result = self.match_url( decodedPayload )
					if http_result==1 and self.resultSet['result']:
						return True
				except:
					pass
			### Match Alpha2 zero tolerance Shellcode
			if self.displayShellCode:
				print "starting Alpha2 zero tolerance matching ..."
				sys.stdout.flush()
			match = self.alpha2endchar.search( self.shellcode )
			if match:
				endChar = match.groups()[0]
				load = match.groups()[1]
				payload = load[27:]
				find_encoded = re.compile('(.*?)%s' % (endChar), re.S)
				match = find_encoded.search(payload)
				if match:
					encoded = match.groups()[0]
					shell_length = len(encoded)
					if self.handle_alpha2zero( encoded, shell_length ):
						return True
			### Match Bergheim shellcode
			if self.displayShellCode:
				print "starting Bergheim matching ..."
				sys.stdout.flush()
			match = self.bergheim.search( self.shellcode )
			if match:
				key = struct.unpack('B',match.groups()[0])[0]
				self.resultSet['xorkey'] = key
				self.log_obj.log("found bergheim xor decoder (key: %s)" % (key), 9, "info", False, True)
				dec_shellcode = self.decrypt_xor(key, self.shellcode)
				if self.handle_bergheim(key, dec_shellcode):
					return True
			### Ende
			self.resultSet['result'] = False
		except KeyboardInterrupt:
			raise
		except:
			f = StringIO.StringIO()
			traceback.print_exc(file=f)
			print f.getvalue()
			sys.exit(0)
		return False

	def handle_pexalphanum(self, decoder, payload):
		### Metasploit PexAlphaNumeric
		payloadSize = len(payload)
		self.log_obj.log("AlphaNum payload size: %s" % (payloadSize), 9, "debug", False, True)
		if payloadSize % 2 != 0:
			payloadSize -= 1
		decodedMessage = {}
		for i in xrange(0, payloadSize, 2):
			decodedMessage[i] = '\x90'
			lowBit = (struct.unpack('B', payload[i])[0] - 1) ^ 0x41
			highBit = struct.unpack('B', payload[i+1])[0] & 0x0f
			resultBit = lowBit | (highBit << 4)
			decodedMessage[i/2] = struct.pack('B',resultBit)
		dec_shellcode = "".join(decodedMessage.values())

		m = self.pexalphanum_bindport.search( dec_shellcode )
		if m:
			raw_port = m.groups()[0]
			port = struct.unpack('!H',raw_port)[0]
			self.resultSet['port'] = port
			self.resultSet['found'] = "bindport"
			bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
			self.resultSet['dlident'] = bindportID
			self.log_obj.log("found pexalphanum bindshell (port: %s)" % (port), 9, "info", False, True)
			self.resultSet['result'] = True
			bindURL = "bind://%s:%s/" % (self.ownIP, port)
			self.resultSet['displayURL'] = bindURL
			self.resultSet['shellcodeName'] = "pexalphanum"
			return True
		else:
			self.write_hexdump( dec_shellcode )
			return False

	def handle_alpha2zero(self, payload, length):
		### Metasploit Alpha2 zero tolerance
		if length % 2 != 0:
			length -= 1
		decodedMessage = {}
		for i in xrange(0, length, 2):
			decodedMessage[i] = '\x90'
			first = struct.unpack('B', payload[i])[0]
			second = struct.unpack('B', payload[i+1])[0]
			C = (first & 0xf0) >> 4
			D = first & 0x0f
			E = (second & 0xf0) >> 4
			B = second & 0x0f
			A = (D ^ E)
			resultBit = (A << 4) + B
			decodedMessage[i/2] = struct.pack('B',resultBit)
		decoded_shellcode = "".join(decodedMessage.values())
		### connectback shell (reverse shell)
		match = self.alpha2connback.search( decoded_shellcode )
		if match:
			raw_ip = match.groups()[0]
			ip = struct.unpack('I',raw_ip)[0]
			ip = struct.pack('I',ip)
			ip = socket.inet_ntoa(ip)
			raw_port = match.groups()[1]
			port = struct.unpack('!H',raw_port)[0]
			if self.replace_locals and self.check_local(ip):
				ip = self.attIP
			elif self.check_local(ip):
				self.resultSet['isLocalIP'] = True
			self.log_obj.log("found alpha2 connectback shell (port: %s ip: %s)" % (port, ip), 9, "info", False, True)
			self.resultSet['dlident'] = "%s%s" % (ip.replace('.',''), port)
			self.resultSet['host'] = ip
			self.resultSet['port'] = port
			self.resultSet['found'] = "connbackshell"
			self.resultSet['result'] = True
			cbackURL = "cbacks://%s:%s/" % (ip, port)
			self.resultSet['displayURL'] = cbackURL
			self.resultSet['shellcodeName'] = "alpha2zero"
			return True
		### bindshell
		match = self.alpha2bind.search( decoded_shellcode )
		if match:
			raw_port = match.groups()[0]
			port = struct.unpack('!H',raw_port)[0]
			self.resultSet['port'] = port
			self.resultSet['found'] = "bindport"
			bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
			self.resultSet['dlident'] = bindportID
			self.log_obj.log("found alpha2 bindshell (port: %s)" % (port), 9, "info", False, True)
			self.resultSet['result'] = True
			bindURL = "bind://%s:%s/" % (self.ownIP, port)
			self.resultSet['displayURL'] = bindURL
			self.resultSet['shellcodeName'] = "alpha2zero"
			return True
		return False

	def handle_wuerzburg(self, key):
		m = False
		filename = "None"
		dec_shellcode = self.decrypt_xor(key, self.shellcode)
		m = self.wuerzburg_file.search( dec_shellcode )
		if m:
			filename = str(m.groups()[0]).replace('\\','')
		return filename

	def handle_aachen(self, ip_key, port_key):
		m = False
		m = self.aachen_connback.search( self.shellcode )
		if m:
			raw_port = m.groups()[0]
			port = struct.unpack('!H',raw_port)[0]^port_key
			raw_ip = m.groups()[1]
			ip = struct.unpack('I',raw_ip)[0]
			ip = struct.pack('I',ip^ip_key)
			ip = socket.inet_ntoa(ip)
			if self.replace_locals and self.check_local(ip):
				ip = self.attIP
			elif self.check_local(ip):
				self.resultSet['isLocalIP'] = True
			self.log_obj.log("found aachen connectback shell (port: %s ip: %s)" % (port, ip), 9, "info", False, True)
			self.resultSet['dlident'] = "%s%s" % (ip.replace('.',''), port)
			self.resultSet['host'] = ip
			self.resultSet['port'] = port
			self.resultSet['found'] = "connbackshell"
			self.resultSet['result'] = True
			cbackURL = "cbacks://%s:%s/" % (ip, port)
			self.resultSet['displayURL'] = cbackURL
			self.resultSet['shellcodeName'] = "aachen"
			return True
		else:
			return False
	
	def handle_bergheim(self, key, dec_shellcode):
		m = False
		### bergheim ConnectBack Shellcode
		m = self.bergheim_connback.search( dec_shellcode )
		if m:
			raw_port = m.groups()[0]
			port = struct.unpack('!H',raw_port)[0]
			raw_ip = m.groups()[1]
			ip = struct.unpack('I',raw_ip)[0]
			ip = struct.pack('I',ip)
			ip = socket.inet_ntoa(ip)
			if self.replace_locals and self.check_local(ip):
				ip = self.attIP
			elif self.check_local(ip):
				self.resultSet['isLocalIP'] = True
			self.log_obj.log("found bergheim shellcode (key: %s port: %s, ip: %s)" % (key, port, ip), 9, "info", False, True)
			dlident = "%s%s" % (ip.replace('.',''), port)
			self.resultSet['dlident'] = dlident
			self.resultSet['result'] = True
			self.resultSet['host'] = ip
			self.resultSet['port'] = port
			self.resultSet['found'] = "connbackshell"
			cbackURL = "cbacks://%s:%s/" % (ip, port)
			self.resultSet['displayURL'] = cbackURL
			self.resultSet['shellcodeName'] = "bergheim"
			return True
		return False
			
	
	def handle_langenfeld(self, key, dec_shellcode):
		m = False
		### langenfeld ConnectBack Shellcode
		m = self.langenfeld_connback.search( dec_shellcode )
		if not m:
			m = self.langenfeld_connback2.search( dec_shellcode )
		if m:
			raw_port = m.groups()[0]
			port = struct.unpack('!H',raw_port)[0]
			raw_ip = m.groups()[1]
			ip = struct.unpack('I',raw_ip)[0]
			ip = struct.pack('I',ip)
			ip = socket.inet_ntoa(ip)
			if self.replace_locals and self.check_local(ip):
				ip = self.attIP
			elif self.check_local(ip):
				self.resultSet['isLocalIP'] = True
			self.log_obj.log("found langenfeld shellcode (key: %s port: %s, ip: %s)" % (key, port, ip), 9, "info", False, True)
			dlident = "%s%s" % (ip.replace('.',''), port)
			self.resultSet['dlident'] = dlident
			self.resultSet['result'] = True
			self.resultSet['host'] = ip
			self.resultSet['port'] = port
			self.resultSet['found'] = "connbackshell"
			cbackURL = "cbacks://%s:%s/" % (ip, port)
			self.resultSet['displayURL'] = cbackURL
			self.resultSet['shellcodeName'] = "langenfeld"
			return True
		return False

	def handle_heidelberg(self, key, dec_shellcode):
		return True

	def handle_bielefeld(self, key, dec_shellcode):
		m = False
		### Mainz / Bielefeld - BindPort Shellcode 1
		m = self.mainz_bindport1.search( dec_shellcode )
		if m:
			raw_port = m.groups()[0]
			port = struct.unpack('!H',raw_port)[0]
			self.resultSet['port'] = port
			self.resultSet['found'] = "bindport"
			self.resultSet['result'] = True
			bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
			self.resultSet['dlident'] = bindportID
			self.log_obj.log("found mainz shellcode (key: %s port: %s)" % (key, port), 9, "info", False, True)
			bindURL = "bind://%s:%s/" % (self.ownIP, port)
			self.resultSet['displayURL'] = bindURL
			self.resultSet['shellcodeName'] = "mainz"
			return True
		### Mainz / Bielefeld - BindPort Shellcode 2
		m = self.mainz_bindport2.search( dec_shellcode )
		if m:
			raw_port = m.groups()[0]
			port = struct.unpack('!H',raw_port)[0]
			self.resultSet['port'] = port
			self.resultSet['found'] = "bindport"
			self.resultSet['result'] = True
			bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
			self.resultSet['dlident'] = bindportID
			self.log_obj.log("found mainz shellcode (key: %s port: %s)" % (key, port), 9, "info", False, True)
			bindURL = "bind://%s:%s/" % (self.ownIP, port)
			self.resultSet['displayURL'] = bindURL
			self.resultSet['shellcodeName'] = "mainz"
			return True
		### Mainz / Bielefeld - ConnectBack Shellcode 1
		m = self.mainz_connback1.search( dec_shellcode )
		if m:
			raw_port = m.groups()[0]
			port = struct.unpack('!H',raw_port)[0]
			raw_ip = m.groups()[1]
			ip = struct.unpack('I',raw_ip)[0]
			ip = struct.pack('I',ip)
			ip = socket.inet_ntoa(ip)
			if self.replace_locals and self.check_local(ip):
				ip = self.attIP
			elif self.check_local(ip):
				self.resultSet['isLocalIP'] = True
			self.log_obj.log("found bielefeld shellcode (key: %s port: %s, ip: %s)" % (key, port, ip), 9, "info", False, True)
			dlident = "%s%s" % (ip.replace('.',''), port)
			self.resultSet['dlident'] = dlident
			self.resultSet['result'] = True
			self.resultSet['host'] = ip
			self.resultSet['port'] = port
			self.resultSet['found'] = "connbackshell"
			cbackURL = "cbacks://%s:%s/" % (ip, port)
			self.resultSet['displayURL'] = cbackURL
			self.resultSet['shellcodeName'] = "bielefeld"
			return True
		### Mainz / Bielefeld - ConnectBack Shellcode 2
		m = self.mainz_connback2.search( dec_shellcode )
		if m:
			raw_ip = m.groups()[0]
			ip = struct.unpack('I',raw_ip)[0]
			ip = struct.pack('I',ip)
			ip = socket.inet_ntoa(ip)
			if self.replace_locals and self.check_local(ip):
				ip = self.attIP
			elif self.check_local(ip):
				self.resultSet['isLocalIP'] = True
			raw_port = m.groups()[1]
			port = struct.unpack('!H',raw_port)[0]
			self.log_obj.log("found bielefeld shellcode (key: %s port: %s, ip: %s)" % (key, port, ip), 9, "info", False, True)
			dlident = "%s%s" % (ip.replace('.',''), port)
			self.resultSet['dlident'] = dlident
			self.resultSet['result'] = True
			self.resultSet['host'] = ip
			self.resultSet['port'] = port
			self.resultSet['found'] = "connbackshell"
			cbackURL = "cbacks://%s:%s/" % (ip, port)
			self.resultSet['displayURL'] = cbackURL
			self.resultSet['shellcodeName'] = "bielefeld"
			return True
		### Mainz / Bielefeld - ConnectBack Shellcode 3
		m = self.mainz_connback3.search( dec_shellcode )
		if m:
			raw_port = m.groups()[0]
			port = struct.unpack('!H',raw_port)[0]
			raw_ip = m.groups()[1]
			ip = struct.unpack('I',raw_ip)[0]
			ip = struct.pack('I',ip)
			ip = socket.inet_ntoa(ip)
			if self.replace_locals and self.check_local(ip):
				ip = self.attIP
			elif self.check_local(ip):
				self.resultSet['isLocalIP'] = True
			self.log_obj.log("found bielefeld shellcode (key: %s port: %s, ip: %s)" % (key, port, ip), 9, "info", False, True)
			dlident = "%s%s" % (ip.replace('.',''), port)
			self.resultSet['dlident'] = dlident
			self.resultSet['result'] = True
			self.resultSet['host'] = ip
			self.resultSet['port'] = port
			self.resultSet['found'] = "connbackshell"
			cbackURL = "cbacks://%s:%s/" % (ip, port)
			self.resultSet['displayURL'] = cbackURL
			self.resultSet['shellcodeName'] = "bielefeld"
			return True
		### Mainz / Bielefeld - embedded URL
		http_result = self.match_url( dec_shellcode )
		if http_result==1 and self.resultSet['result']:
			return True
		return False

	def handle_ulm(self, keys):
		m1 = False
		m2 = False
		i = 0
		while i<=len(keys):
			dec_shellcode = self.decrypt_multi_xor(keys, self.shellcode, i)
			m1 = self.ulm_bindshell.search( dec_shellcode )
			m2 = self.ulm_connback.search( dec_shellcode )
			if m1 or m2:
				break
			i += 1
		if m1:
			raw_port = m1.groups()[0]
			port = struct.unpack('!H',raw_port)[0]
			self.resultSet['port'] = port
			self.resultSet['found'] = "bindport"
			self.resultSet['result'] = True
			bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
			self.resultSet['dlident'] = bindportID
			self.log_obj.log("found ulm shellcode (key: %s, port: %s)" % (keys, port), 9, "info", False, True)
			bindURL = "bind://%s:%s/" % (self.ownIP, port)
			self.resultSet['displayURL'] = bindURL
			self.resultSet['shellcodeName'] = "ulm"
			return True
		if m2:
			raw_ip = m2.groups()[0]
			ip = struct.unpack('I',raw_ip)[0]
			ip = struct.pack('I',ip)
			ip = socket.inet_ntoa(ip)
			if self.replace_locals and self.check_local(ip):
				ip = self.attIP
			elif self.check_local(ip):
				self.resultSet['isLocalIP'] = True
			raw_port = m2.groups()[1]
			port = struct.unpack('!H',raw_port)[0]
			self.log_obj.log("found ulm shellcode (key: %s, ip: %s, port: %s)" % (keys, ip, port), 9, "info", False, True)
			dlident = "%s%s" % (ip.replace('.',''), port)
			self.resultSet['dlident'] = dlident
			self.resultSet['result'] = True
			self.resultSet['host'] = ip
			self.resultSet['port'] = port
			self.resultSet['found'] = "connbackshell"
			cbackURL = "cbacks://%s:%s/" % (ip, port)
			self.resultSet['displayURL'] = cbackURL
			self.resultSet['shellcodeName'] = "ulm"
			return True
		return False

	def handle_adenau(self, keys):
		m1 = False
		m2 = False
		i = 0
		while i<=len(keys):
			dec_shellcode = self.decrypt_multi_xor(keys, self.shellcode, i)
			dec_shellcode2 = self.decrypt_multi_xor(keys, self.shellcode2, i)
			m1 = self.adenau_bindport.search( dec_shellcode )
			m2 = self.adenau_bindport.search( dec_shellcode2 )
			if m1 or m2:
				break
			i += 1
		if m1:
			raw_port = m1.groups()[0]
			port = struct.unpack('!H',raw_port)[0]
			self.resultSet['port'] = port
			self.resultSet['found'] = "bindport"
			self.resultSet['result'] = True
			bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
			self.resultSet['dlident'] = bindportID
			self.log_obj.log("found adenau shellcode (key: %s, port: %s)" % (keys, port), 9, "info", False, True)
			bindURL = "bind://%s:%s/" % (self.ownIP, port)
			self.resultSet['displayURL'] = bindURL
			self.resultSet['shellcodeName'] = "adenau"
			return True
		if m2:
			raw_port = m2.groups()[0]
			port = struct.unpack('!H',raw_port)[0]
			self.resultSet['port'] = port
			self.resultSet['found'] = "bindport"
			self.resultSet['result'] = True
			bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
			self.resultSet['dlident'] = bindportID
			self.log_obj.log("found adenau shellcode (key: %s, port: %s)" % (keys, port), 9, "info", False, True)
			bindURL = "bind://%s:%s/" % (self.ownIP, port)
			self.resultSet['displayURL'] = bindURL
			self.resultSet['shellcodeName'] = "adenau"
			return True
		return False

	def handle_rothenburg(self, keys):
		m1 = False
		m2 = False
		m3 = False
		i = 0
		while i<=len(keys):
			dec_shellcode = self.decrypt_multi_xor(keys, self.shellcode, i)
			#self.write_hexdump(dec_shellcode, "unknown")
			m1 = self.rothenburg_bindport.search( dec_shellcode )
			m2 = self.schoenborn_connback.search( dec_shellcode )
			m3 = self.rothenburg_bindport2.search( dec_shellcode )
			if m1 or m2 or m3:
				break
			i += 1
		if m1:
			raw_port = m1.groups()[0]
			port = struct.unpack('!H',raw_port)[0]
			self.resultSet['port'] = port
			self.resultSet['found'] = "bindport"
			self.resultSet['result'] = True
			bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
			self.resultSet['dlident'] = bindportID
			self.log_obj.log("found rothenburg shellcode 1 (key: %s, port: %s)" % (keys, port), 9, "info", False, True)
			bindURL = "bind://%s:%s/" % (self.ownIP, port)
			self.resultSet['displayURL'] = bindURL
			self.resultSet['shellcodeName'] = "rothenburg"
			return True
		if m2:
			raw_ip = m2.groups()[0]
			ip = struct.unpack('I',raw_ip)[0]
			ip = struct.pack('I',ip)
			ip = socket.inet_ntoa(ip)
			if self.replace_locals and self.check_local(ip):
				ip = self.attIP
			elif self.check_local(ip):
				self.resultSet['isLocalIP'] = True
			raw_port = m2.groups()[1]
			port = struct.unpack('!H',raw_port)[0]
			self.log_obj.log("found schoenborn shellcode (key: %s, ip: %s, port: %s)" % (keys, ip, port), 9, "info", False, True)
			dlident = "%s%s" % (ip.replace('.',''), port)
			self.resultSet['dlident'] = dlident
			self.resultSet['result'] = True
			self.resultSet['host'] = ip
			self.resultSet['port'] = port
			self.resultSet['found'] = "connbackshell"
			cbackURL = "cbacks://%s:%s/" % (ip, port)
			self.resultSet['displayURL'] = cbackURL
			self.resultSet['shellcodeName'] = "schoenborn"
			return True
		if m3:
			raw_port = m3.groups()[0]
			port = struct.unpack('!H',raw_port)[0]
			self.resultSet['port'] = port
			self.resultSet['found'] = "bindport"
			self.resultSet['result'] = True
			bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
			self.resultSet['dlident'] = bindportID
			self.log_obj.log("found rothenburg shellcode 2 (key: %s, port: %s)" % (keys, port), 9, "info", False, True)
			bindURL = "bind://%s:%s/" % (self.ownIP, port)
			self.resultSet['displayURL'] = bindURL
			self.resultSet['shellcodeName'] = "rothenburg"
			return True
		else:
			return False

	def handle_siegburg(self, key, dec_shellcode):
		m = False
		m = self.siegburg_bindshell.search( dec_shellcode)
		if m:
			raw_port = m.groups()[0]
			port = struct.unpack('!H',raw_port)[0]
			self.log_obj.log("found siegburg shellcode (key: %s, port: %s)" % (key, port), 9, "info", False, True)
			self.resultSet['port'] = port
			self.resultSet['found'] = "bindport"
			self.resultSet['result'] = True
			bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
			self.resultSet['dlident'] = bindportID
			bindURL = "bind://%s:%s/" % (self.ownIP, port)
			self.resultSet['displayURL'] = bindURL
			self.resultSet['shellcodeName'] = "siegburg"
			return True
		else:
			return False

	def handle_koeln(self, keys):
		m = False
		i = 0
		while i<=len(keys):
			dec_shellcode = self.decrypt_multi_xor(keys, self.shellcode, i)
			m = self.koeln_bindport.search( dec_shellcode )
			if m:
				break
			i += 1
		if m:
			raw_port = m.groups()[0]
			port = struct.unpack('!H',raw_port)[0]
			self.resultSet['port'] = port
			self.resultSet['found'] = "bindport"
			self.resultSet['result'] = True
			bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
			self.resultSet['dlident'] = bindportID
			self.log_obj.log("found koeln shellcode (key: %s, port: %s)" % (keys, port), 9, "info", False, True)
			bindURL = "bind://%s:%s/" % (self.ownIP, port)
			self.resultSet['displayURL'] = bindURL
			self.resultSet['shellcodeName'] = "koeln"
			return True
		else:
			return False

	def handle_linkbot(self, key, dec_shellcode):
		m = False
		m = self.linkbot_connback.search( dec_shellcode )
		if m:
			raw_ip = m.groups()[0]
			ip = struct.unpack('I',raw_ip)[0]
			ip = struct.pack('I',ip)
			ip = socket.inet_ntoa(ip)
			if self.replace_locals and self.check_local(ip):
				ip = self.attIP
			elif self.check_local(ip):
				self.resultSet['isLocalIP'] = True
			raw_port = m.groups()[1]
			port = struct.unpack('!H',raw_port)[0]
			authkey = base64.b64encode(m.groups()[2])
			self.log_obj.log('found lindau (linkbot) connectback transfer 1 (ip: %s port: %s auth: %s)' % (ip, port, authkey), 9, "info", False, True)
			self.resultSet['found'] = "connectbackfiletrans"
			self.resultSet['passwort'] = authkey
			self.resultSet['dlident'] = "%s%s" % (ip.replace('.',''), port)
			self.resultSet['host'] = ip
			self.resultSet['port'] = port
			self.resultSet['result'] = True
			cbackURL = "cbackf://%s:%s/%s" % (ip, port, authkey)
			self.resultSet['displayURL'] = cbackURL
			self.resultSet['shellcodeName'] = "linkbot"
			return True
		m = self.linkbot_connback2.search( dec_shellcode )
		if m:
			raw_ip = m.groups()[0]
			ip = struct.unpack('I',raw_ip)[0]
			ip = struct.pack('I',ip)
			ip = socket.inet_ntoa(ip)
			if self.replace_locals and self.check_local(ip):
				ip = self.attIP
			elif self.check_local(ip):
				self.resultSet['isLocalIP'] = True
			raw_port = m.groups()[1]
			port = struct.unpack('!H',raw_port)[0]
			authkey = base64.b64encode(m.groups()[2])
			self.log_obj.log('found lindau (linkbot) connectback transfer 2 (ip: %s port: %s auth: %s)' % (ip, port, authkey), 9, "info", False, True)
			self.resultSet['found'] = "connectbackfiletrans"
			self.resultSet['passwort'] = authkey
			self.resultSet['dlident'] = "%s%s" % (ip.replace('.',''), port)
			self.resultSet['host'] = ip
			self.resultSet['port'] = port
			self.resultSet['result'] = True
			cbackURL = "cbackf://%s:%s/%s" % (ip, port, authkey)
			self.resultSet['displayURL'] = cbackURL
			self.resultSet['shellcodeName'] = "linkbot"
			return True
		m = self.linkbot_connback3.search( dec_shellcode )
		if m:
			raw_ip = m.groups()[1]
			ip = struct.unpack('I',raw_ip)[0]
			ip = struct.pack('I',ip)
			ip = socket.inet_ntoa(ip)
			if self.replace_locals and self.check_local(ip):
				ip = self.attIP
			elif self.check_local(ip):
				self.resultSet['isLocalIP'] = True
			raw_port = m.groups()[0]
			port = struct.unpack('!H',raw_port)[0]
			authkey = base64.b64encode(m.groups()[2])
			self.log_obj.log('found lindau (linkbot) connectback transfer 3 (ip: %s port: %s auth: %s)' % (ip, port, authkey), 9, "info", False, True)
			self.resultSet['found'] = "connectbackfiletrans"
			self.resultSet['passwort'] = authkey
			self.resultSet['dlident'] = "%s%s" % (ip.replace('.',''), port)
			self.resultSet['host'] = ip
			self.resultSet['port'] = port
			self.resultSet['result'] = True
			cbackURL = "cbackf://%s:%s/%s" % (ip, port, authkey)
			self.resultSet['displayURL'] = cbackURL
			self.resultSet['shellcodeName'] = "linkbot"
			return True
		return False

	def handle_schauenburg(self, key, dec_shellcode):
		m = False
		m = self.schauenburg_bindport.search( dec_shellcode )
		if m:
			raw_port = m.groups()[0]
			port = struct.unpack('!H',raw_port)[0]
			self.resultSet['port'] = port
			self.resultSet['found'] = "bindport"
			self.resultSet['result'] = True
			bindportID = "%s%s" % (self.ownIP.replace('.',''), port)
			self.resultSet['dlident'] = bindportID
			self.log_obj.log("found schauenburg bindport (key: %s, port: %s)" % (key, port), 9, "info", False, True)
			bindURL = "bind://%s:%s/" % (self.ownIP, port)
			self.resultSet['displayURL'] = bindURL
			self.resultSet['shellcodeName'] = "schauenburg"
			return True
		m = False
		m = self.schauenburg_connback.search( dec_shellcode )
		if m:
			raw_ip = m.groups()[0]
			ip = struct.unpack('I',raw_ip)[0]
			ip = struct.pack('I',ip)
			ip = socket.inet_ntoa(ip)
			raw_port = m.groups()[1]
			port = struct.unpack('!H',raw_port)[0]
			if self.replace_locals and self.check_local(ip):
				ip = self.attIP
			elif self.check_local(ip):
				self.resultSet['isLocalIP'] = True
			self.log_obj.log("found schauenburg reverse shell (key: %s port: %s, ip: %s)" % (key, port, ip), 9, "info", False, True)
			dlident = "%s%s" % (ip.replace('.',''), port)
			self.resultSet['dlident'] = dlident
			self.resultSet['result'] = True
			self.resultSet['host'] = ip
			self.resultSet['port'] = port
			self.resultSet['found'] = "connbackshell"
			cbackURL = "cbackf://%s:%s/" % (ip, port)
			self.resultSet['displayURL'] = cbackURL
			self.resultSet['shellcodeName'] = "schauenburg"
			return True
		return False

	def handle_berlin(self, key, dec_shellcode):
		m = self.ftpcmdExpre.search( dec_shellcode )
		if m:
			self.log_obj.log("Windows CMD FTP checking", 9, "crit", True, False)
			ip = m.groups()[0]
			cipmatch = self.checkIPExpre.search(ip)
			if cipmatch:
				local = self.check_local(ip)
				if local and self.replace_locals:
					ip = self.attIP
				elif local and not self.replace_locals:
					self.resultSet['isLocalIP'] = True
					self.log_obj.log("local IP found" , 6, "crit", True, True)
			else:
				self.log_obj.log("no IP: %s" % (ip) , 6, "crit", True, True)
			port = m.groups()[1]
			user = m.groups()[2]
			passw = m.groups()[3]
			filename = m.groups()[4]
			filename = self.checkFTPcmdFilename(filename)
			self.log_obj.log("found Windows CMD FTP (server: %s:%s user: %s:%s file: %s)" % (ip,port,user,passw,filename), 9, "info", True, False)
			self.resultSet['host'] = ip
			self.resultSet['port'] = int(port) % 65551
			self.resultSet['found'] = "ftp"
			self.resultSet['username'] = user
			self.resultSet['passwort'] = passw
			self.resultSet['path'] = [filename]
			self.resultSet['result'] = True
			self.resultSet['dlident'] = "%s%i%s" % (self.resultSet['host'].replace('.',''), self.resultSet['port'], filename.replace('/',''))
			ftpURL = "ftp://%s:%s@%s:%s%s" % (user,passw,ipself.resultSet['port'],filename)
			self.resultSet['displayURL'] = ftpURL
			self.resultSet['shellcodeName'] = "berlin"
			return True

	def handle_leimbach(self, key, dec_shellcode):
		m = self.tftpExpre.search( dec_shellcode )
		if m:
			tftp_command = m.groups()[0]
			ip = m.groups()[2]
			if self.replace_locals and self.check_local(ip):
				ip = self.attIP
			elif self.check_local(ip):
				self.resultSet['isLocalIP'] = True
			get_command = m.groups()[3]
			file = m.groups()[4]
			self.log_obj.log("found leimbach tftp download (key: %s, ip: %s, file: %s)" % (key,ip,file), 9, "info", False, True)
			dlident = "%s%s" % (ip.replace('.',''),file)
			self.resultSet['dlident'] = dlident
			self.resultSet['result'] = True
			self.resultSet['host'] = ip
			self.resultSet['port'] = 69
			self.resultSet['path'] = file
			self.resultSet['found'] = "tftp"
			tftpURL = "tftp://%s:%s/%s" % (ip,self.resultSet['port'],file)
			self.resultSet['displayURL'] = tftpURL
			self.resultSet['shellcodeName'] = "leimbach"
			return True
		### Leimbach - embedded URL
		if self.match_plainTFTP(dec_shellcode) and self.resultSet['result']:
			return True
		http_result = self.match_url( dec_shellcode )
		if http_result==1 and self.resultSet['result']:
			return True

	def handle_lichtenfels(self, key, dec_shellcode):
		m = self.lichtenfels_connback.search( dec_shellcode )
		if m:
			raw_port = m.groups()[0]
			port = struct.unpack('!H',raw_port)[0]
			raw_ip = m.groups()[1]
			ip = struct.unpack('I',raw_ip)[0]
			ip = struct.pack('I',ip)
			ip = socket.inet_ntoa(ip)
			if self.replace_locals and self.check_local(ip):
				ip = self.attIP
			elif self.check_local(ip):
				self.resultSet['isLocalIP'] = True
			self.log_obj.log("found lichtenfels shellcode (key: %s port: %s, ip: %s)" % (key, port, ip), 9, "info", False, True)
			dlident = "%s%s" % (ip.replace('.',''), port)
			self.resultSet['dlident'] = dlident
			self.resultSet['result'] = True
			self.resultSet['host'] = ip
			self.resultSet['port'] = port
			self.resultSet['found'] = "connbackshell"
			connbackURL = "cbacks://%s:%s/" % (ip, port)
			self.resultSet['displayURL'] = connbackURL
			self.resultSet['shellcodeName'] = "lichtenfels"
			return True
		else:
			return False

	def write_hexdump(self, shellcode=None, extension=None, ownPort="None"):
		if not shellcode:
			file_data = "".join(self.shellcode)
		else:
			file_data = "".join(shellcode)

		### ignore zero size hexdumps
		if len(file_data)==0:
			return

		### md5
		hash = hashlib.md5(file_data)
		digest = hash.hexdigest()
		if extension!=None:
			filename = "hexdumps/%s-%s-%s.hex" % (extension.strip(), digest, ownPort)
		else:
			filename = "hexdumps/%s-%s.hex" % (digest, ownPort)
		if not os.path.exists(filename):
			fp = open(filename, 'a+')
			fp.write(file_data)
			fp.close()
			self.log_obj.log("(%s) no match, writing hexdump (%s :%s) - %s" % (self.attIP, digest, len(file_data), self.resultSet['vulnname']), 9, "warn", True, True)
		return

	def match_url(self, dec_shellcode="None"):
		try:
			if dec_shellcode=="None":
				match = self.urlExpre.search( self.shellcode )
			else:
				match = self.urlExpre.search( dec_shellcode )
			if self.displayShellCode:
				print "starting AnyURL matching ..."
				sys.stdout.flush()
			if match:
				#self.write_hexdump(self.shellcode, "http")
				path = match.groups()[0]
				url_obj = urlparse.urlsplit(path)
				if self.config_dict['verbose_logging']==1:
					self.log_obj.log("found path: %s (%s)" % (path, url_obj), 9, "debug", True, True)
				### ('http', '192.168.116.2:5806', '/x.exe', '', '')
				### ('ftp', 'bla:bla@natout.sfldlib.org:22679', '/bot.exe', '', '')
				#if (url_obj[0]!='http' and url_obj[0]!='ftp') or len(url_obj[1])<7 or len(url_obj[2])<1 or url_obj[1].count(':')==0:
				if (url_obj[0]!='http' and url_obj[0]!='ftp') or len(url_obj[1])<7 or len(url_obj[2])<1:
					self.log_obj.log("(%s) found unknown/incomplete download URL: %s (%s)" % (self.attIP, match.groups(),self.resultSet['vulnname']), 9, "div", True, False)
					return 2
				if url_obj[0]=='http':
					#self.write_hexdump(self.shellcode, "URL")
					new_url = []
					new_url.append(url_obj[0])
					if url_obj[1].count(':')>0:
						(dl_host, dl_port) = url_obj[1].split(':')
						if len(dl_port)<=0:
							dl_port = '80'
					else:
						dl_host = url_obj[1]
						dl_port = '80'
					### host ersetzen falls locate addresse
					ipmatch = self.checkIPExpre.search(dl_host)
					if ipmatch:
						if self.replace_locals and self.check_local(dl_host):
							dl_host = self.attIP
						elif self.check_local(dl_host):
							self.resultSet['isLocalIP'] = True
					new_url.append("%s:%s" % (dl_host, dl_port))
					new_url.append(url_obj[2])
					new_url.append(url_obj[3])
					new_url.append(url_obj[4])
					new_url.append('')
					found_url = urlparse.urlunparse(new_url)
					dlident = "%s%s%s" % (dl_host.replace('.',''),dl_port,url_obj[2].replace('/',''))
					if len(url_obj[3])>0:
						http_path = "%s?%s" % (url_obj[2], url_obj[3])
					else:
						http_path = url_obj[2]
					self.resultSet['path'] = http_path
					self.resultSet['host'] = dl_host
					self.resultSet['port'] = dl_port
					self.resultSet['dlident'] = dlident
					self.resultSet['displayURL'] = found_url
					self.resultSet['found'] = "httpurl"
					self.resultSet['result'] = True
					self.resultSet['shellcodeName'] = "plainurl"
					self.log_obj.log("found download URL: %s" % (found_url), 9, "info", False, True)
					return 1
				elif url_obj[0]=='ftp':
					(userpass, hostport) = url_obj[1].split('@')
					(username, passwort) = userpass.split(':')
					(hostname, port) = hostport.split(':')
					### if ip and not hostname check replace locals
					ipmatch = self.checkIPExpre.search(hostname)
					if ipmatch:
						if self.replace_locals and self.check_local(hostname):
							hostname = self.attIP
						elif self.check_local(hostname):
							self.resultSet['isLocalIP'] = True
					dlident = "%s%s%s" % (hostname.replace('.',''),port,url_obj[2].replace('/',''))
					self.resultSet['result'] = True
					self.resultSet['found'] = "ftp"
					self.resultSet['host'] = hostname
					self.resultSet['port'] = port
					self.resultSet['username'] = username
					self.resultSet['passwort'] = passwort
					self.resultSet['path'] = [url_obj[2].replace('/','')]
					self.resultSet['dlident'] = dlident
					ftpURL = "ftp://%s:%s@%s:%s/%s" % (username,passwort,hostname,port,self.resultSet['path'])
					self.resultSet['displayURL'] = ftpURL
					self.resultSet['shellcodeName'] = "plainurl"
					self.log_obj.log("found download URL: %s" % (path), 9, "info", True, True)
					return 1
			### no match found
			return 0
		except KeyboardInterrupt:
			raise

	def checkFTPcmdFilename(self, filename):
		try:
			if filename.find('&echo')>0:
				filelist = filename.split('&echo')
				filename = filelist[1].strip()
			return filename
		except KeyboardInterrupt:
			raise

	def check_local(self, host):
		try:
			for localAddress in self.localIPliste:
				if localAddress.contains(str(host)):
					self.log_obj.log("local ip address found %s replacing with %s" % (host,self.attIP), 9, "div", False, False)
					return True
			return False
		except KeyboardInterrupt:
			raise
		except:
			return False


	def match_plainFTP(self, dec_shellcode=None):
		try:
			### Match Plain FTP CMD 3 shellcode
			if self.displayShellCode:
				print "starting Plain FTP CMD 3 Shell matching ..."
				sys.stdout.flush()
			if dec_shellcode==None:
				ShellcodeToAnalyse = self.shellcode
			else:
				ShellcodeToAnalyse = dec_shellcode
			match = self.ftpcmd3IPExpre.search(ShellcodeToAnalyse)
			if match:
				ip = match.groups()[0]
				position = ShellcodeToAnalyse.rfind(ip)
				Cutshellcode = ShellcodeToAnalyse[position:]
				cipmatch = self.checkIPExpre.search(ip)
				if cipmatch:
					local = self.check_local(ip)
					if local and self.replace_locals:
						ip = self.attIP
					elif local and not self.replace_locals:
						self.resultSet['isLocalIP'] = True
						self.log_obj.log("local IP found" , 6, "crit", True, True)
				else:
					self.log_obj.log("no IP: %s" % (ip) , 6, "crit", True, True)
				port = match.groups()[1]
				if port==None:
					port = 21
				if int(port)<1 or int(port)>65550:
					self.log_obj.log("wrong port: %s" % (port), 6, "crit", True, False)
					return False
				match2 = self.ftpcmd3UserPassExpre.search(Cutshellcode)
				if match2:
					if match2.groups()[0] != None:
						user = match2.groups()[0].strip()
						passw = match2.groups()[1].strip()
					elif match2.groups()[2] != None:
						user = match2.groups()[2].strip()
						passw = match2.groups()[3].strip()
					elif match2.groups()[4] != None:
						user = match2.groups()[4].strip()
						passw = match2.groups()[5].strip()
					else:
						user = match2.groups()[6].strip()
						passw = match2.groups()[7].strip()
					match3 = self.ftpcmd3BinExpre.findall(Cutshellcode)
					if match3:
						filenameList = []
						for fileMatch in match3:
							if fileMatch.count(' ')<=0:
								filenameList.append(fileMatch.strip())
							else:
								moreThanOneList = fileMatch.split(' ')
								for moreItem in moreThanOneList:
									if moreItem!='':
										filenameList.append(moreItem)
						filenameList = list(sets.Set(filenameList))
						self.log_obj.log("found Windows CMD 3 FTP (server: %s:%s user: %s:%s file: %s)" % (ip,port,user,passw,filenameList), 9, "info", True, False)
						self.resultSet['host'] = ip
						self.resultSet['port'] = int(port)
						self.resultSet['found'] = "ftp"
						self.resultSet['username'] = user
						self.resultSet['passwort'] = passw
						self.resultSet['path'] = filenameList
						self.resultSet['result'] = True
						self.resultSet['dlident'] = "%s%i%s" % (ip.replace('.',''),self.resultSet['port'],filenameList[0].replace('/',''))
						ftpURL = "ftp://%s:%s@%s:%s/%s" % (user, passw, ip, self.resultSet['port'], filenameList)
						self.resultSet['displayURL'] = ftpURL
						self.resultSet['shellcodeName'] = "plainftp"
						return True
					else:
						if self.config_dict['verbose_logging']==1:
							self.log_obj.log("no file found: %s" % (Cutshellcode), 9, "crit", True, False)
						return False
				else:
					if self.config_dict['verbose_logging']==1:
						self.log_obj.log("no username/password found: %s" % (Cutshellcode), 9, "crit", True, False)
					return False
			else:
				if self.config_dict['verbose_logging']==1:
					self.log_obj.log("no remote host found: %s" % (ShellcodeToAnalyse), 9, "crit", True, False)
				return False
			return False
		except KeyboardInterrupt:
			raise

	def macht_FTPold(self):
		try:
			### Match Plain FTP CMD Shell shellcode
			if self.displayShellCode:
				print "starting Plain FTP CMD Shell matching ..."
				sys.stdout.flush()
			match = self.ftpcmdExpre.search(self.shellcode)
			if match:
				#self.log_obj.log("Windows CMD FTP checking", 9, "crit", True, False)
				ip = match.groups()[0]
				cipmatch = self.checkIPExpre.search(ip)
				if cipmatch:
					local = self.check_local(ip)
					if local and self.replace_locals:
						ip = self.attIP
					elif local and not self.replace_locals:
						self.resultSet['isLocalIP'] = True
						self.log_obj.log("local IP found" , 6, "crit", True, True)
				else:
					self.log_obj.log("no IP: %s" % (ip) , 6, "crit", True, True)
				port = match.groups()[1]
				user = match.groups()[2]
				passw = match.groups()[3]
				filename = match.groups()[4]
				filename = self.checkFTPcmdFilename(filename)
				self.log_obj.log("found Windows CMD FTP (server: %s:%s user: %s:%s file: %s)" % (ip,port,user,passw,filename), 9, "info", True, False)
				self.resultSet['host'] = ip
				self.resultSet['port'] = int(port) % 65551
				self.resultSet['found'] = "ftp"
				self.resultSet['username'] = user
				self.resultSet['passwort'] = passw
				self.resultSet['path'] = [filename]
				self.resultSet['result'] = True
				self.resultSet['dlident'] = "%s%i%s" % (ip.replace('.',''), self.resultSet['port'], filename.replace('/',''))
				ftpURL = "ftp://%s:%s@%s:%s/%s" % (user, passw, ip, self.resultSet['port'], filename)
				self.resultSet['displayURL'] = ftpURL
				self.resultSet['shellcodeName'] = "plainftpold"
				return True
			### Match Plain FTP CMD 2 Shell shellcode
			if self.displayShellCode:
				print "starting Plain FTP CMD 2 Shell matching ..."
				sys.stdout.flush()
			match = self.ftpcmd2Expre.search(self.shellcode)
			if match:
				#self.log_obj.log("Windows CMD FTP 2 checking", 9, "crit", True, False)
				###('hack95fy.3322.or', None, 'sb', 'sb', 'ftp.txt\r\necho bin>>ftp.txt\r\necho get sx.exe>>', 'sx.exe', 'ftp.txt\r\necho get qq.exe>>', 'qq.exe', 'ftp.txt\r\necho get 3389.exe>>', '3389.exe')
				#print match.groups()
				ip = match.groups()[0]
				if self.replace_locals and self.check_local(ip):
					ip = self.attIP
				elif self.check_local(ip):
					self.resultSet['isLocalIP'] = True
				port = match.groups()[1]
				if port==None:
					port = 21
				user = match.groups()[2]
				passw = match.groups()[3]
				filename1 = match.groups()[5]
				filename2 = match.groups()[7]
				filename3 = match.groups()[9]
				files = [filename1]
				if filename2!=None:
					files.append(filename2)
				if filename3!=None:
					files.append(filename3)
				self.log_obj.log("found Windows CMD FTP 2 (server: %s:%s user: %s:%s file: %s)" % (ip,port,user,passw,files), 9, "info", True, False)
				self.resultSet['host'] = ip
				self.resultSet['port'] = int(port) % 65551
				self.resultSet['found'] = "ftp"
				self.resultSet['username'] = user
				self.resultSet['passwort'] = passw
				self.resultSet['path'] = files
				self.resultSet['result'] = True
				self.resultSet['dlident'] = "%s%i" % (ip.replace('.',''), self.resultSet['port'])
				self.resultSet['displayURL'] = "ftp://%s:%s@%s:%s/%s" % (user, passw, ip, self.resultSet['port'], files)
				self.resultSet['shellcodeName'] = "plainftpold"
				return True
			return False
		except KeyboardInterrupt:
			raise

	def match_plainTFTP(self, dec_shellcode=None):
		try:
			### Match Plain TFTP 1 CMD Shell shellcode
			if self.displayShellCode:
				print "starting Plain TFTP 1 CMD Shell matching ..."
				sys.stdout.flush()
			if dec_shellcode==None:
				match = self.tftpExpre1.search(self.shellcode)
			else:
				match = self.tftpExpre1.search(dec_shellcode)
			if match:
				#self.log_obj.log("Windows CMD TFTP 1 checking", 9, "crit", True, False)
				if match.groups()[2]!=None:
					ip = match.groups()[2]
					file = match.groups()[4]
				else:
					ip = match.groups()[7]
					file = match.groups()[9]
				if self.replace_locals and self.check_local(ip):
					ip = self.attIP
				elif self.check_local(ip):
					self.resultSet['isLocalIP'] = True
				self.log_obj.log("found Windows CMD TFTP 1 (server: %s file: %s)" % (ip,file), 9, "info", True, False)
				dlident = "%s%s" % (ip.replace('.',''),file)
				self.resultSet['dlident'] = dlident
				self.resultSet['host'] = ip
				self.resultSet['port'] = 69
				self.resultSet['path'] = file
				self.resultSet['found'] = "tftp"
				tftpURL = "tftp://%s:%s/%s" % (ip,self.resultSet['port'],file)
				self.resultSet['displayURL'] = tftpURL
				self.resultSet['result'] = True
				self.resultSet['shellcodeName'] = "plaintftp"
				return True
			### Match Plain TFTP CMD Shell shellcode
			if self.displayShellCode:
				print "starting Plain TFTP 2 CMD Shell matching ..."
				sys.stdout.flush()
			if dec_shellcode==None:
				match = self.tftpExpre.search(self.shellcode)
			else:
				match = self.tftpExpre.search(dec_shellcode)
			if match:
				#self.log_obj.log("Windows CMD TFTP checking", 9, "crit", True, False)
				ip = match.groups()[2]
				if self.replace_locals and self.check_local(ip):
					ip = self.attIP
				elif self.check_local(ip):
					self.resultSet['isLocalIP'] = True
				file = match.groups()[4]
				self.log_obj.log("found Windows CMD TFTP (server: %s file: %s)" % (ip,file), 9, "info", True, False)
				dlident = "%s%s" % (ip.replace('.',''),file)
				self.resultSet['dlident'] = dlident
				self.resultSet['host'] = ip
				self.resultSet['port'] = 69
				self.resultSet['path'] = file
				self.resultSet['found'] = "tftp"
				tftpURL = "tftp://%s:%s/%s" % (ip,self.resultSet['port'],file)
				self.resultSet['displayURL'] = tftpURL
				self.resultSet['result'] = True
				self.resultSet['shellcodeName'] = "plaintftp"
				return True
			return False
		except KeyboardInterrupt:
			raise
