<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:output method="text" />

    <!-- Match everything -->
    <xsl:template match="@*|node()">
        <xsl:apply-templates select="AzurePublicIpAddresses" />
    </xsl:template>

    <xsl:template match="AzurePublicIpAddresses">
        <xsl:text>#!/usr/bin/env python&#xa;&#xa;</xsl:text>
        <xsl:text>from netaddr import IPNetwork&#xa;</xsl:text>
        <xsl:text>import sys&#xa;</xsl:text>
        <xsl:text>import os&#xa;</xsl:text>
        <xsl:text>&#xa;</xsl:text>
        <xsl:text>ip_dict = </xsl:text>
        <xsl:text>{&#xa;</xsl:text>
        <xsl:apply-templates select="Region" />
        <xsl:text>}&#xa;&#xa;</xsl:text>
        <xsl:text>for region in ip_dict.keys():&#xa;</xsl:text>
        <xsl:text>    print("Region: {0}".format(region))&#xa;</xsl:text>
        <xsl:text>    for cidr in ip_dict[region]:&#xa;</xsl:text>
        <xsl:text>        ipnet = IPNetwork(cidr)&#xa;</xsl:text>
        <xsl:text>        cmd = "python cert_scanner.py -s {0} -e {1} -t 32".format(ipnet[0], ipnet[-1])&#xa;</xsl:text>
        <xsl:text>        print("RUNNING: {0}".format(cmd))&#xa;</xsl:text>
        <xsl:text>        os.system(cmd)&#xa;&#xa;</xsl:text>
    </xsl:template>

    <xsl:template match="Region">
        <xsl:text>    '</xsl:text><xsl:value-of select="@Name" /><xsl:text>'</xsl:text>
        <xsl:text>: [&#xa;</xsl:text>
        <xsl:apply-templates select="IpRange" />
        <xsl:text>    ],&#xa;</xsl:text>
    </xsl:template>

    <xsl:template match="IpRange">
        <xsl:text>        '</xsl:text><xsl:value-of select="@Subnet" /><xsl:text>',&#xa;</xsl:text>
    </xsl:template>
</xsl:stylesheet>
