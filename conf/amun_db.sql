-- MySQL dump 10.11
--
-- Host: localhost    Database: amun_db
-- ------------------------------------------------------

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Current Database: `amun_db`
--

CREATE DATABASE /*!32312 IF NOT EXISTS*/ `amun_db` /*!40100 DEFAULT CHARACTER SET latin1 */;

USE `amun_db`;

--
-- Table structure for table `amun_binaries`
--

DROP TABLE IF EXISTS `amun_binaries`;
CREATE TABLE `amun_binaries` (
  `id` bigint(20) NOT NULL,
  `binary_data` longblob NOT NULL,
  PRIMARY KEY  (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

--
-- Table structure for table `amun_cwsandbox`
--

DROP TABLE IF EXISTS `amun_cwsandbox`;
CREATE TABLE `amun_cwsandbox` (
  `id` int(11) NOT NULL,
  `cwanalyse` longtext NOT NULL,
  `flag` int(11) NOT NULL,
  `comment` varchar(255) NOT NULL,
  `timestamp` timestamp NULL default NULL,
  `priority` smallint(6) NOT NULL default '0',
  `notification_email` text,
  `binary_data` mediumblob,
  PRIMARY KEY  (`id`),
  KEY `priority` (`priority`,`id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

--
-- Table structure for table `amun_storage`
--

DROP TABLE IF EXISTS `amun_storage`;
CREATE TABLE `amun_storage` (
  `id` int(11) NOT NULL auto_increment,
  `md5hash` varchar(32) NOT NULL,
  `filesize` int(11) NOT NULL,
  `comment` varchar(255) NOT NULL,
  PRIMARY KEY  (`id`),
  UNIQUE KEY `md5hash` (`md5hash`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2008-11-05  9:47:06
