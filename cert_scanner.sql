-- MySQL dump 10.13  Distrib 5.7.18, for macos10.12 (x86_64)
--
-- Host: localhost    Database: cert_scanner
-- ------------------------------------------------------
-- Server version	5.7.18

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
-- Table structure for table `cert_names`
--

DROP TABLE IF EXISTS `cert_names`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `cert_names` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `cips_id` int(11) NOT NULL,
  `name` varchar(253) NOT NULL,
  `type` varchar(10) DEFAULT NULL,
  `exp_date` varchar(45) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `name_INDEX` (`name`),
  KEY `cips_FK_idx` (`cips_id`),
  KEY `exp_date_INDEX` (`exp_date`),
  CONSTRAINT `cips_FK` FOREIGN KEY (`cips_id`) REFERENCES `checked_ips` (`id`) ON DELETE CASCADE ON UPDATE NO ACTION
) ENGINE=InnoDB AUTO_INCREMENT=275829 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `checked_ips`
--

DROP TABLE IF EXISTS `checked_ips`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `checked_ips` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ipstr` varchar(15) NOT NULL,
  `ip` int(11) unsigned NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ip_UNIQUE` (`ip`),
  KEY `ip_INDEX` (`ip`)
) ENGINE=InnoDB AUTO_INCREMENT=2421248 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2018-05-28 18:10:03

-- Set up the initial user, you should change the password here and in the code.
CREATE USER 'certscanner'@'%';
GRANT ALL PRIVILEGES ON cert_scanner.* To 'certscanner'@'%' IDENTIFIED BY 'Y0uSh0uldCh@ng3This!';
