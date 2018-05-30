# SSL_Catalog
Scan IP ranges and store pertinent SSL information for later data mining.  Currently the Expire Date, IP, Name, and Subject alternative names are stored.

I have also written an MPI version of this scanner that lets you run on HPC clusters.  The MPI version greatly decreases the time it takes to catalog the internet (depending on the size of your cluster of course).  This version has the lowest barrier to entry, as you don't need a cluster set up to run it.  You do, however need a database named *cert_scanner* which can be populated via *cert_scanner.sql* as follows:

        echo "CREATE DATABASE cert_scanner;" | mysql -u <user> -p"<password>"
        mysql -u <user> -p"<password>" cert_scanner < cert_scanner.sql

My MPI version is a bit more flexible, but I'm still actively making changes to it.  Thus, I'll create a new repo for it as soon as I'm completely happy with it, and when I have time to document 1). The OpenHPC cluster setup.  2). How the code is distributed and run on that cluster.

# Prerequisites

* You need the following Python packages installed

        pip install netaddr requests future pyOpenSSL dateparser ndg-httpsclient pyasn1 MySQL-python

# Help

* Everything you should need to know can be obtained command line as follows:

        python cert_scanner.py -h

* *cert_reader.py* can be manipulated to use OpenSSL or Python's ssl alternative for reading certs.

# Typical Run

        python cert_scanner.py -s 13.52.0.0 -e 13.52.255.255 -t 16

# Scan Published Cloud IP Ranges

* I've included a couple simple helper scripts to get you going, though *azure.py* should be updated.
* I use these lists to target and/or exclude the ranges I want to catalog.
** The provided code targets only.

## Scan Azsure IPs

* Download IP in XML format from here https://www.microsoft.com/en-us/download/confirmation.aspx?id=41653
* Use helpers/Azure.xsl to transform download into a Python runnable.

        xsltproc helpers/Azure.xsl PublicIPs_20180524.xml > azure.py

* Run the generated azsure.py script to scan its IP ranges.

        python azure.py

## Scan Amazon IPs

* Notes on getting this list can be found [AWS IP Address Ranges](https://docs.aws.amazon.com/general/latest/gr/aws-ip-ranges.html#aws-ip-download "AWS IP Address Range")

* Or simply run the below commad:

        python amazon.py

## Other Providers

* Many providers have these lists, and you can find most of them via Google Search.

# Protect Your Servers Behind Cloudflare

* Use this Gist to protect Linux servers behind Cloudflare [Cloudflare Ipset Gist](https://gist.github.com/viable-hartman/3093796be4ec66710f20e7bdf3576724 "Cloudflare Ipset Gist")

* Schedule the above Gist to run at a regular frequency.  I run it every 6 hours.
