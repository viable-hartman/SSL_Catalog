#!/usr/bin/env python

from netaddr import IPNetwork
import requests
import os

ip_ranges = requests.get('https://ip-ranges.amazonaws.com/ip-ranges.json').json()['prefixes']
amazon_ips = [item['ip_prefix'] for item in ip_ranges if item["service"] == "AMAZON"]
ec2_ips = [item['ip_prefix'] for item in ip_ranges if item["service"] == "EC2"]

# I purposefully ignore Amazon IPs here because I really only care about EC2
for cidr in ec2_ips:
    ipnet = IPNetwork(cidr)
    cmd = "python cert_scanner.py -s {0} -e {1} -t 32".format(ipnet[0], ipnet[-1])
    print("RUNNING: {0}".format(cmd))
    os.system(cmd)
