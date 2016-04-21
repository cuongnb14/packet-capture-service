#!/usr/bin/env python
"""
Use DPKT to read in packets of network interface and print out the contents of the packets
This example is focused on the fields in the Ethernet Frame and IP packet
"""
import dpkt
from datetime import datetime
import socket
import pcap
import logging

logger = logging.getLogger("mpcap")
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(message)s')
fh = logging.FileHandler("mpcap.log")
fh.setLevel(logging.DEBUG)
fh.setFormatter(formatter)
logger.addHandler(fh)


def mac_addr(mac_string):
    """Print out MAC address given a string

    
    @param mac_string: the string representation of a MAC address
    @return printable MAC address
    """
    return ':'.join('%02x' % ord(b) for b in mac_string)


def ip_to_str(address):
    """Print out an IP address given a string

    @param address: the string representation of a MAC address
    @return printable IP address
    """
    return socket.inet_ntop(socket.AF_INET, address)


def packet_handler(timestamp, buf):
	try:
		str_timestamp = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
		str_ipdst = None
		str_ipsrc = None

		# Print out the timestamp in UTC
		print 'Timestamp: ', str_timestamp

	    # Unpack the Ethernet frame (mac src/dst, ethertype)
		eth = dpkt.ethernet.Ethernet(buf)
		print 'Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type

		if eth.type == dpkt.ethernet.ETH_TYPE_IP:
			ip = eth.data
			str_ipdst = ip_to_str(ip.dst)
			str_ipsrc = ip_to_str(ip.src)

		logger.info('%s::%s::%s', str_timestamp, str_ipsrc, str_ipdst)
	    # Make sure the Ethernet frame contains an IP packet
	    # EtherType (IP, ARP, PPPoE, IP6... see http://en.wikipedia.org/wiki/EtherType)
		if eth.type != dpkt.ethernet.ETH_TYPE_IP:
			print 'Non IP Packet type not supported %s\n' % eth.data.__class__.__name__
			return

	    # Now unpack the data within the Ethernet frame (the IP packet) 
	    # Pulling out src, dst, length, fragment info, TTL, and Protocol
		ip = eth.data

	    # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
		do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
		more_fragments = bool(ip.off & dpkt.ip.IP_MF)
		fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

	    
	    # Print out the info
		print 'IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % \
	          (ip_to_str(ip.src), ip_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset)
	except Exception, e:
		print e.message

pc = pcap.pcap(name="wlan0", timeout_ms=10000, immediate=True)
#pc.setfilter('tcp')
pc.loop(packet_handler)

