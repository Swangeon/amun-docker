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

import time
import amun_logging
import amun_config_parser
import logging

class log:
	def __init__(self):
		try:
			self.log_name = "Log Experiment"
			### create logfile 
			logfile = "logs/log_experiment.log"
			self.expLogger = logging.getLogger("amun-exp")
			hdlr = logging.handlers.TimedRotatingFileHandler(logfile, 'midnight')
			formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
			hdlr.setFormatter(formatter)
			self.expLogger.addHandler(hdlr)
			self.expLogger.setLevel(10)
			#filename = "logs/log-experiment.log"
			#self.fh = open(filename, 'a+')
		except KeyboardInterrupt:
			raise

	def __del__(self):
		try:
			self.fh.close()
		except:
			pass

	def initialConnection(self, attackerIP, attackerPort, victimIP, victimPort, identifier, initialConnectionsDict, loLogger):
		""" log incoming initial connections """
		pass

	def incoming(self, attackerIP, attackerPort, victimIP, victimPort, vulnName, timestamp, downloadMethod, loLogger, attackerID, shellcodeName):
		""" log successfull exploit and download offer """
		message = "Exploit: %s -> victimIP:%s %s (%s)" % (attackerIP,victimPort,vulnName,downloadMethod)
		self.expLogger.info(message)

	def successfullSubmission(self, attackerIP, attackerPort, victimIP, downloadURL, md5hash, data, filelength, downMethod, loLogger, vulnName, fexists):
		""" log successfull download """
		pass
