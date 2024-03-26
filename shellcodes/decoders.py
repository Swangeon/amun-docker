"""
[Amun - low interaction honeypot]
Copyright (C) [2008]  [Jan Goebel]

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, see <http://www.gnu.org/licenses/>
"""

### collection of known shellcode decoders

try:
	import psyco ; psyco.full()
	from psyco.classes import *
except ImportError:
	pass

import re

class decoders:
	def __init__(self):
		self.decodersDict = {}

		### CheckIP
		self.log("compiling CheckIP Expression", 0, "info")
		checkIPExpression = re.compile('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
		self.decodersDict['checkIP'] = checkIPExpression
		del checkIPExpression

		### HTTP/HTTPS/FTP - thanks to 
		self.log("compiling URL decoder", 0, "info")
		URLExpression = re.compile('((https?|ftp):((\/\/)|(\\\\))+[\d\w:@\/()~_?\+\-=\\\.&]*)')
		self.decodersDict['url'] = URLExpression
		del URLExpression

		### TFTP 1
		self.log("compiling TFTP 1 decoder", 0, "info")
		TFTPExpression1 = re.compile("tftp(\.exe)?\s*(\-i)?\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s*(GET).*?&\s*(\S*?\.exe)|tftp(\.exe)?\s*(\-i)?\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s*(GET).*?\s*(\S*?\.exe)", re.S|re.I)
		self.decodersDict['tftp1'] = TFTPExpression1
		del TFTPExpression1

		### TFTP 2
		self.log("compiling TFTP decoder", 0, "info")
		TFTPExpression = re.compile('.*(tftp(.exe)? -i) ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}) (get) (.*?\.(exe|com)).*', re.S|re.I)
		self.decodersDict['tftp'] = TFTPExpression
		del TFTPExpression

		### FTP cmd
		self.log("compiling Windows CMD FTP 1", 0, "info")
		FTPcmdExpression = re.compile('.*cmd /[c|k].*echo open ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[a-z0-9\.]*) ([0-9]+).*[>|>>]\s*.+&echo user (.*?) (.*?) >>.*&echo get (.*?) >>.*', re.S|re.I)
		self.decodersDict['ftpcmd'] = FTPcmdExpression
		del FTPcmdExpression

		### FTP command 2
		self.log("compiling Windows CMD FTP 2", 0, "info")
		FTPcmd2Expression = re.compile('.*echo open ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|[a-z0-9\.]+).([0-9]+)?>>.*?echo (.*?)>>.*?echo (.*?)>>.*?(.*?get (.*?)>>).*?(.*?get (.*?)>>)?.*?(.*?get (.*?)>>)?', re.S|re.I)
		self.decodersDict['ftpcmd2'] = FTPcmd2Expression
		del FTPcmd2Expression

		### FTP command 3
		self.log("compiling Windows CMD FTP 3", 0, "info")
		#FTPcmd3IPExpression = re.compile('.*open ([@a-zA-Z0-9\-\/\\\.\+:]+) ([0-9]+).*', re.S|re.I)
		FTPcmd3IPExpression = re.compile('open\s*([@a-zA-Z0-9\-\/\\\.\+:]+)\s*([0-9]+)?.*', re.S|re.I)
		#FTPcmd3UserPassExpression = re.compile('>.*?&echo user (.*?) (.*?)>>|>>.*?&echo (.*?)>>.*?&echo (.*?)&', re.S|re.I)
		FTPcmd3UserPassExpression = re.compile('>.*?&echo user (.*?) (.*?)>>|>>.*?&echo (.*?)>>.*?&echo (.*?)&|.*?@echo (.*?)>>.*?@echo (.*?)>>|>.*?echo (.*?)>>.*?echo (.*?)>>', re.S|re.I)
		FTPcmd3BinaryExpression = re.compile('echo get (.*?)>>', re.S|re.I)
		FTPcmd3BinaryExpression = re.compile('echo [m?]get (.*?)>>', re.S|re.I)
		FTPcmd3BinaryExpression = re.compile('echo m?get (.*?)>>', re.S|re.I)
		self.decodersDict['ftpcmd3ip'] = FTPcmd3IPExpression
		self.decodersDict['ftpcmd3userpass'] = FTPcmd3UserPassExpression
		self.decodersDict['ftpcmd3binary'] = FTPcmd3BinaryExpression
		del FTPcmd3IPExpression
		del FTPcmd3UserPassExpression
		del FTPcmd3BinaryExpression

		### Unnamed Bindshell 1
		self.log("compiling bindshell1 pattern", 0, "info")
		BINDExpression = re.compile('\\x58\\x99\\x89\\xe1\\xcd\\x80\\x96\\x43\\x52\\x66\\x68(..)\\x66\\x53\\x89\\xe1\\x6a\\x66\\x58\\x50\\x51\\x56', re.S)
		self.decodersDict['bindshell1'] = BINDExpression
		del BINDExpression

		### Unnamed Bindshell 2
		self.log("compiling bindshell2 pattern", 0, "info")
		BINDExpression2 = re.compile('\\x53\\x53\\x53\\x53\\x53\\x43\\x53\\x43\\x53\\xff\\xd0\\x66\\x68(..)\\x66\\x53\\x89\\xe1\\x95\\x68\\xa4\\x1a', re.S)
		self.decodersDict['bindshell2'] = BINDExpression2
		del BINDExpression2

		### Unnamed Bindshell 3
		self.log("compiling bindshell3 pattern", 0, "info")
		BINDExpression3 = re.compile('\\x89\\xc3\\x31\\xff\\x57\\x57\\x68\\x02\\x00(..)\\x89\\xe6\\x6a', re.S)
		self.decodersDict['bindshell3'] = BINDExpression3
		del BINDExpression3

		### Unnamed Bindshell 4
		self.log("compiling bindshell4 pattern", 0, "info")
		BINDExpression4 = re.compile('\\xc0\\x33\\xdb\\x50\\x50\\x50\\xb8\\x02\\x01(..)\\xfe\\xcc\\x50', re.S)
		self.decodersDict['bindshell4'] = BINDExpression4
		del BINDExpression4

		### Rothenburg Shellcode
		self.log("compiling rothenburg xor decoder", 0, "info")
		rothenburg = re.compile('\\xd9\\x74\\x24\\xf4\\x5b\\x81\\x73\\x13(.)(.)(.)(.)\\x83\\xeb\\xfc\\xe2\\xf4', re.S)
		self.decodersDict['rothenburg'] = rothenburg
		rothenburg_port_expre = re.compile('\\x53\\x53\\x53\\x53\\x53\\x43\\x53\\x43\\x53\\xff\\xd0\\x66\\x68(..)\\x66\\x53\\x89\\xe1', re.S)
		self.decodersDict['rothenburg_bindport'] = rothenburg_port_expre
		schoenborn_port_ip_expre = re.compile('\\x53\\x53\\x53\\x43\\x53\\x43\\x53\\xff\\xd0\\x68(....)\\x66\\x68(..)\\x66\\x53\\x89\\xe1', re.S)
		self.decodersDict['schoenborn_connback'] = schoenborn_port_ip_expre
		rothenburg_port_expre2 = re.compile('\\x96\\x43\\x52\\x66\\x68(..)\\x66\\x53\\x89\\xe1\\x6a', re.S)
		self.decodersDict['rothenburg_bindport2'] = rothenburg_port_expre2
		del rothenburg
		del rothenburg_port_expre
		del schoenborn_port_ip_expre
		del rothenburg_port_expre2

		### Aachen Shellcode
		self.log("compiling aachen xor decoder", 0, "info")
		aachen = re.compile('\\x8b\\x45\\x04\\x35(....)\\x89\\x45\\x04\\x66\\x8b\\x45\\x02\\x66\\x35(..)\\x66\\x89\\x45\\x02', re.S)
		self.decodersDict['aachen'] = aachen
		aachen_port_ip_expre = re.compile('\\x90\\xeb\\x25(..)(....)\\x02\\x06\\x6c', re.S)
		self.decodersDict['aachen_connback'] = aachen_port_ip_expre
		del aachen
		del aachen_port_ip_expre

		### Adenau Shellcode
		self.log("compiling adenau xor decoder", 0, "info")
		adenau = re.compile('\\xeb\\x19\\x5e\\x31\\xc9\\x81\\xe9....\\x81\\x36(.)(.)(.)(.)\\x81\\xee\\xfc\\xff\\xff\\xff', re.S)
		self.decodersDict['adenau'] = adenau
		adenau_port_expre = re.compile('\\x50\\x50\\x50\\x40\\x50\\x40\\x50\\xff\\x56\\x1c\\x8b\\xd8\\x57\\x57\\x68\\x02\\x00(..)\\x8b\\xcc\\x6a', re.S)
		#adenau_port_expre = re.compile('\\x57\\x57\\x68\\x02\\x00(..)\\xd8\\x55', re.S)
		self.decodersDict['adenau_bindport'] = adenau_port_expre
		del adenau
		del adenau_port_expre

		### Heidelberg
		self.log("compiling heidelberg xor decoder", 0, "info")
		heidelberg = re.compile('\\x33\\xc9\\x66\\xb9..\\x80\\x34.(.)\\xe2.\\x42\\xff\\xe2\\xe8\\xea\\xff\\xff', re.S)
		self.decodersDict['heidelberg'] = heidelberg
		del heidelberg

		### Mainz / Bielefeld Shellcode
		self.log("compiling mainz/bielefeld xor decoder", 0, "info")
		mainz = re.compile('\\x33\\xc9\\x66\\xb9..\\x80\\x34.(.)\\xe2.\\xeb\\x05\\xe8\\xeb\\xff\\xff\\xff', re.S)
		self.decodersDict['mainz'] = mainz
		del mainz
		### bind 1
		mainz1_port_expre = re.compile('\\x6a\\x01\\x6a\\x02\\xff\\x57\\xec\\x8b\\xd8\\xc7\\x07\\x02\\x00(..)\\x33\\xc0\\x89\\x47\\x04', re.S)
		self.decodersDict['mainz_bindport1'] = mainz1_port_expre
		del mainz1_port_expre
		### bind 2
		mainz2_port_expre = re.compile('\\x6a\\x01\\x6a\\x02\\xff\\x57\\xec\\x8b\\xd8\\xc7\\x07\\x02\\x00(..)\\xc0\\x89\\x47\\x04', re.S)
		self.decodersDict['mainz_bindport2'] = mainz2_port_expre
		del mainz2_port_expre
		### connback 1
		mainz1_port_ip_expre = re.compile('\\xc7\\x02\\x63\\x6d\\x64\\x00\\x52\\x50\\xff\\x57\\xe8\\xc7\\x07\\x02\\x00(..)\\xc7\\x47\\x04(....)\\x6a\\x10\\x57\\x53\\xff\\x57\\xf8\\x53\\xff\\x57\\xfc\\x50\\xff\\x57\\xec', re.S)
		self.decodersDict['mainz_connback1'] = mainz1_port_ip_expre
		del mainz1_port_ip_expre
		### connback 2
		mainz2_port_ip_expre = re.compile('\\x50\\x50\\x50\\x40\\x50\\x40\\x50\\xff\\x56.\\x8b\\xd8\\x68(....)\\x68\\x02\\x00(..)\\x8b\\xcc\\x6a.\\x51\\x53', re.S)
		self.decodersDict['mainz_connback2'] = mainz2_port_ip_expre
		del mainz2_port_ip_expre
		### connback 3
		mainz3_port_ip_expre = re.compile('\\x50\\x50\\x8d\\x57\\x3c\\xc7\\x02....\\x52\\x50\\xff\\x57\\xe8\\xc7\\x07\\x02\\x00(..)\\xc7\\x47\\x04(....)\\x10\\x57.\\xff\\x57.\\x53\\xff\\x57.\\x50', re.S)
		self.decodersDict['mainz_connback3'] = mainz3_port_ip_expre
		del mainz3_port_ip_expre

		### Wuerzburg Shellcode
		self.log("compiling wuerzburg xor decoder", 0, "info")
		wuerzburg = re.compile('\\xeb\\x27(..)(....)\\x5d\\x33\\xc9\\x66\\xb9..\\x8d\\x75\\x05\\x8b\\xfe\\x8a\\x06\\x3c.\\x75\\x05\\x46\\x8a\\x06..\\x46\\x34(.)\\x88\\x07\\x47\\xe2\\xed\\xeb\\x0a\\xe8\\xda\\xff\\xff\\xff', re.S)
		self.decodersDict['wuerzburg'] = wuerzburg
		wuerzburg_filename = re.compile('\\x00\\x50\\x00\\x50\\x2e(.*?)\\x00\\x50\\x00\\x50', re.S)
		self.decodersDict['wuerzburg_file'] = wuerzburg_filename
		del wuerzburg
		del wuerzburg_filename

		### Schauenburg Shellcode
		self.log("compiling schauenburg xor decoder", 0, "info")
		schauenburg = re.compile('\\xeb\\x0f\\x8b\\x34\\x24\\x33\\xc9\\x80\\xc1.\\x80\\x36(.)\\x46\\xe2\\xfa\\xc3\\xe8\\xec', re.S)
		self.decodersDict['schauenburg'] = schauenburg
		schauenburg_port_expre = re.compile('\\xff\\xd0\\x93\\x6a.\\x68\\x02\\x00(..)\\x8b\\xc4\\x6a.\\x50\\x53', re.S)
		self.decodersDict['schauenburg_bindport'] = schauenburg_port_expre
		schauenburg_connback = re.compile('\\x00\\x57\\xff\\x16\\xff\\xd0\\x93\\x68(....)\\x68\\x02\\x00(..)\\x8b\\xc4\\x6a.\\x50\\x53', re.S)
		self.decodersDict['schauenburg_connback'] = schauenburg_connback
		del schauenburg
		del schauenburg_port_expre
		del schauenburg_connback

		### Koeln Shellcode
		self.log("compiling koeln xor decoder", 0, "info")
		koeln = re.compile('\\xd9\\xee\\xd9\\x74\\x24\\xf4\\x5b\\x31\\xc9\\xb1.\\x81\\x73\\x17(.)(.)(.)(.)\\x83\\xeb.\\xe2', re.S)
		self.decodersDict['koeln'] = koeln
		koeln_port_expre = re.compile('\\x40\\x50\\x40\\x50\\xff\\x55.\\x89\\xc7\\x31\\xdb\\x53\\x53\\x68\\x02\\x00(..)\\x89\\xe0\\x6a.\\x50\\x57', re.S)
		self.decodersDict['koeln_bindport'] = koeln_port_expre
		del koeln
		del koeln_port_expre

		### Lichtenfels Shellcode
		self.log("compiling lichtenfels xor decoder", 0, "info")
		lichtenfels = re.compile('\\x01\\xfc\\xff\\xff\\x83\\xe4\\xfc\\x8b\\xec\\x33\\xc9\\x66\\xb9..\\x80\\x30(.)\\x40\\xe2\\xfA', re.S)
		self.decodersDict['lichtenfels'] = lichtenfels
		lichtenfels_port_ip_expre = re.compile('\\x83\\xf8.\\x74.\\x8b\\xd8\\x66\\xc7\\x45...\\x66\\xc7\\x45\\x02(..)\\xc7\\x45\\x04(....)\\x6a.\\x55\\x53', re.S)
		self.decodersDict['lichtenfels_connback'] = lichtenfels_port_ip_expre
		del lichtenfels
		del lichtenfels_port_ip_expre

		### Mannheim Shellcode
		self.log("compiling mannheim xor decoder", 0, "info")
		mannheim = re.compile('\\x80\\x73\\x0e(.)\\x43\\xe2.*\\x73\\x73\\x73(.+)\\x81\\x86\\x8c\\x81', re.S)
		self.decodersDict['mannheim'] = mannheim
		del mannheim

		### Berlin Shellcode
		self.log("compiling berlin xor decorder", 0, "info")
		berlin = re.compile('\\x31\\xc9\\xb1\\xfc\\x80\\x73\\x0c(.)\\x43\\xe2.\\x8b\\x9f....\\xfc', re.S)
		self.decodersDict['berlin'] = berlin
		del berlin

		### Leimbach Shellcode
		self.log("compiling leimbach xor decoder", 0, "info")
		leimbach = re.compile('\\x5b\\x31\\xc9\\xb1.\\x80\\x73.(.)\\x43\\xe2.[\\x21|\\x20][\\xd3|\\xd2][\\x77|\\x76]', re.S)
		self.decodersDict['leimbach'] = leimbach
		del leimbach

		### PexAlphaNumeric Shellcode (Augsburg)
		self.log("compiling Metasploit PexAlphaNumeric", 0, "info")
		pexalphanum = re.compile('(VTX630VX4A0B6HH0B30BCVX2BDBH4A2AD0ADTBDQB0ADAVX4Z8BDJOM(.*)Z)', re.S)
		self.decodersDict['pexalphanum'] = pexalphanum
		pex_port_expre = re.compile('\\x53\\x53\\x43\\x53\\x43\\x53\\xff\\xd0\\x66\\x68(..)\\x66\\x53\\x89\\xe1\\x95\\x68\\xa4\\x1a\\x70\\xc7', re.S)
		self.decodersDict['pexalphanum_bindport'] = pex_port_expre
		del pexalphanum
		del pex_port_expre

		### Base64Encoded PexAlphaNumeric Shellcode (Augsburg)
		self.log("compiling Base64Encoded PexAlphaNumeric", 0, "info")
		alphaNum = re.compile('LoadTestPassword: (.*)==rrr', re.S)
		self.decodersDict['alphaNum'] = alphaNum
		del alphaNum

		### Base64Encoded PexAlphaNumeric Shellcode 2 (Augsburg)
		self.log("compiling Base64Encoded PexAlphaNumeric 2", 0, "info")
		alphaNum2 = re.compile('LoadTestPassword: (.*)=rrr', re.S)
		self.decodersDict['alphaNum2'] = alphaNum2
		del alphaNum2

		### alpha2 zero-tolerance
		self.log("compiling alpha2 zero-tolerance", 0, "info")
		alpha2endchar = re.compile('\\x51\\x5a\\x6a(.)\\x58.(.*)', re.S)
		alpha2connback = re.compile('\\x53\\x53\\x53\\x53\\x43\\x53\\x43\\x53\\xff\\xd0\\x68(....)\\x66\\x68(..)\\x66\\x53\\x89\\xe1\\x95', re.S)
		alpha2bind = re.compile('\\x53\\x53\\x53\\x53\\x43\\x53\\x43\\x53\\xff\\xd0\\x66\\x68(..)\\x66\\x53\\x89\\xe1\\x95', re.S)
		self.decodersDict['alpha2endchar'] = alpha2endchar
		self.decodersDict['alpha2connback'] = alpha2connback
		self.decodersDict['alpha2bind'] = alpha2bind
		del alpha2endchar
		del alpha2connback
		del alpha2bind

		### Lindau Shellcode
		self.log("compiling lindau (linkbot) xor decoder", 0, "info")
		linkbot = re.compile('\\xeb\\x15\\xb9....\\x81\\xf1.....\\x80\\x74\\x31\\xff(.)\\xe2\\xf9\\xeb\\x05\\xe8\\xe6\\xff\\xff\\xff', re.S)
		self.decodersDict['linkbot'] = linkbot
		linkbot_port_ip_expre = re.compile('\\x53\\x53\\x68(....)\\x68\\x02\\x00(..)\\x8b\\xd4\\x8b\\xd8\\x6a\\x10\\x52\\x53\\xba\\x63\\x30\\x60\\x5a\\xff\\xd6\\x50\\xb4\\x02\\x50\\x55\\x53\\xba\\x00\\x58\\x60\\xe2\\xff\\xd6\\xbf(....)\\xff\\xe5', re.S)
		linkbot_port_ip_expre2 = re.compile('\\x50\\x50\\x68(....)\\x68\\x02\\x00(..)\\x8b\\xfc\\x50\\x6a.\\x6a.\\xff\\x55.\\x8b\\xd8\\x6a.\\x57\\x53\\xff\\x55.\\x85\\xc0\\x75.\\xc7\\x45.....\\x50\\x6a.\\x55\\x53\\xff\\x55.\\x8b\\xf4\\xc7\\x45.....\\x68....\\x68(....)\\x8b\\xfc\\x55\\x57', re.S)
		linkbot_port_ip_expre3 = re.compile('\\x5e\\x5b\\xff\\xe0\\x5e\\x68(..)\\x00\\x00\\x68(....)\\x54\\xba(....)\\xff\\xd6', re.S)
		self.decodersDict['linkbot_connback'] = linkbot_port_ip_expre
		self.decodersDict['linkbot_connback2'] = linkbot_port_ip_expre2
		self.decodersDict['linkbot_connback3'] = linkbot_port_ip_expre3
		del linkbot
		del linkbot_port_ip_expre
		del linkbot_port_ip_expre2
		del linkbot_port_ip_expre3

		### Furth Shellcode
		self.log("compiling furth xor decoder", 0, "info")
		furth = re.compile('\\x5b\\x31\\xc9\\x66\\xb9..\\x80\\x73.(.)\\x43\\xe2..', re.S)
		self.decodersDict['furth'] = furth
		del furth

		### Duesseldorf Shellcode
		self.log("compiling duesseldorf xor decoder",0, "info")
		duesseldorf = re.compile('\\xd9\\x74..\\x5b\\x80\\x73.(.)\\x80\\x73.(.)\\x83..\\xe2.\\x78.\\x18', re.S)
		self.decodersDict['duesseldorf'] = duesseldorf
		del duesseldorf

		### Bergheim Shellcode
		self.log("compiling bergheim xor decoder",0, "info")
		bergheim = re.compile('\\x31\\xc9\\x66\\x81\\xe9..\\x80\\x33(.)\\x43\\xe2\\xfa', re.S)
		self.decodersDict['bergheim'] = bergheim
		bergheim_connback = re.compile('\\x50\\xff\\xd6\\x66\\x53\\x66\\x68(..)\\x68(....)\\x54\\xff\\xd0\\x68', re.S)
		self.decodersDict['bergheim_connback'] = bergheim_connback
		del bergheim
		del bergheim_connback

		### Langenfeld Shellcode
		self.log("compiling langenfeld xor decoder",0, "info")
		langenfeld = re.compile('\\xeb\\x0f\\x5b\\x33\\xc9\\x66\\xb9..\\x80\\x33(.)\\x43\\xe2\\xfa\\xeb', re.S)
		self.decodersDict['langenfeld'] = langenfeld
		langenfeld_connback = re.compile('\\x52\\x50\\xff..\\xc7\\x07\\x02\\x00(..)\\xc7\\x47.(....)\\x6a.\\x57\\x53\\xff', re.S)
		self.decodersDict['langenfeld_connback'] = langenfeld_connback
		langenfeld_connback2 = re.compile('\\x52\\x50\\xff..\\xc7\\x07\\x02\\x00(..)\\xc7\\x47.(....)\\xf4\\xf4\\xf4\\xf4', re.S)
		self.decodersDict['langenfeld_connback2'] = langenfeld_connback2
		del langenfeld
		del langenfeld_connback
		del langenfeld_connback2

		### Bonn Shellcode
		self.log("compiling bonn xor decoder",0, "info")
		bonn = re.compile('\\x31\\xc9\\x81\\xe9....\\x83\\xeb.\\x80\\x73.(.)\\x43\\xe2\\xf9', re.S)
		self.decodersDict['bonn'] = bonn
		del bonn

		### Siegburg Shellcode
		self.log("compiling siegburg xor decoder", 0, "info")
		siegburg = re.compile('\\x31\\xeb\\x80\\xeb.\\x58\\x80\\x30(.)\\x40\\x81\\x38....\\x75.\\xeb', re.S)
		self.decodersDict['siegburg'] = siegburg
		siegburg_bindshell = re.compile('\\x89\\xc7\\x31\\xdb\\x53\\x53\\x68\\x02\\x00(..)\\x89\\xe0\\x6a.\\x50\\x57', re.S)
		self.decodersDict['siegburg_bindshell'] = siegburg_bindshell
		del siegburg
		del siegburg_bindshell

		### Ulm
		self.log("compiling ulm xor decoder", 0, "info")
		ulm = re.compile('\\xff\\xc0\\x5e\\x81\\x76\\x0e(.)(.)(.)(.)\\x83\\xee\\xfc', re.S)
		self.decodersDict['ulm'] = ulm
		ulm_bindshell =  re.compile('\\x53\\x43\\x53\\x43\\x53\\xff\\xd0\\x66\\x68(..)\\x66\\x53\\x89\\xe1\\x95', re.S)
		self.decodersDict['ulm_bindshell'] = ulm_bindshell
		ulm_connback = re.compile('\\x6a.\\xff\\x55.\\x93\\x68(....)\\x68\\x02\\x00(..)\\x89\\xe2\\x6a.\\x6a.\\x6a', re.S)
		self.decodersDict['ulm_connback'] = ulm_connback
		del ulm
		del ulm_bindshell
		del ulm_connback

		### Plain1 Shellcode
		self.log("compiling plain1 shellcode", 0, "info")
		plain1 = re.compile('\\x89\\xe1\\xcd.\\x5b\\x5d\\x52\\x66\\xbd(..)\\x0f\\xcd\\x09\\xdd\\x55\\x6a.\\x51\\x50', re.S)
		self.decodersDict['plain1'] = plain1
		del plain1

		### Plain2 Shellcode
		self.log("compiling plain2 shellcode", 0, "info")
		plain2 = re.compile('\\x50\\x50\\x50\\x50\\x40\\x50\\x40\\x50\\xff\\x56\\x1c\\x8b\\xd8\\x57\\x57\\x68\\x02(..)\\x8b\\xcc\\x6a.\\x51\\x53', re.S)
		self.decodersDict['plain2'] = plain2
		del plain2

	def getDecoders(self):
		return self.decodersDict

	def log(self, message, tabs=0, type="normal"):
		empty = ""
		for i in range(0, tabs):
			empty += " "

		if type=="debug":
			print "\033[0;34m%s.::[Amun - Decoder] %s ::.\033[0m" % (empty, message)
		elif type=="warn":
			print "\033[0;33m%s.::[Amun - Decoder] %s ::.\033[0m" % (empty, message)
		elif type=="info":
			print "\033[0;32m%s.::[Amun - Decoder] %s ::.\033[0m" % (empty, message)
		elif type=="crit":
			print "\033[0;31m%s.::[Amun - Decoder] %s ::.\033[0m" % (empty, message)
		elif type=="fade":
			print "\033[0;37m%s.::[Amun - Decoder] %s ::.\033[0m" % (empty, message)
		elif type=="div":
			print "\033[0;36m%s.::[Amun - Decoder] %s ::.\033[0m" % (empty, message)
		else:
			print "\033[0m%s.::[Amun - Decoder] %s ::.\033[0m" % (empty, message)
