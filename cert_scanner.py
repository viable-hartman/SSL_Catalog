#!/usr/bin/env python

from __future__ import print_function

__version__ = '0.1'
__author__  = 'Trevor Hartman'

from multiprocessing.dummy import Pool as ThreadPool
import sys
import argparse
import threading
import Queue
import json
import MySQLdb
from cert_reader import CertReader, Cert
import time

#import errno  # Uncomment if you add back in error checking in scan function


def getFreeConn():
    global qlock, q
    with qlock:  # This lock may be redundant as q.get()  may lock and block
        while True:
            if not q.empty():
                return q.get()

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def ips(start, end):
    import socket, struct
    start = struct.unpack('>I', socket.inet_aton(start))[0]
    end = struct.unpack('>I', socket.inet_aton(end))[0]
    # if start - end > 130050, i.e. a 2 X class B's
    #   Split the run up...
    if (end - start) > 130050:
        newend = end
        end = start + 130050
        newstart = end
        return {'range': [socket.inet_ntoa(struct.pack('>I', i)) for i in range(start, end)], 'next': {'start': socket.inet_ntoa(struct.pack('>I', newstart)), 'end': socket.inet_ntoa(struct.pack('>I', newend))} }
    return {'range': [socket.inet_ntoa(struct.pack('>I', i)) for i in range(start, end)], 'next': {'start': -1, 'end': -1} }

def scan(ip):
    global q, connect_timeout, port
    cr = CertReader()
    eprint("---- ", ip, "----")
    # Get a free DB connection
    conn = getFreeConn()
    cert_names = None
    try:
        cert = cr.readCert(ip, port, connect_timeout)

        # Get Alt and Issued names
        cert_names = cert.getAllIssuedNames()
        exp_date = cert.getExpDate()

        # Uncomment this print for debugging visurally in real-time
        #print(ip, "\t", json.dumps(cert_names))

        # Uncomment this portion to store results into MySQL
        x = conn.cursor()
        try:
            x.execute("""INSERT INTO checked_ips (ipstr, ip) VALUES("{0}", INET_ATON("{0}"))""".format(ip))
            cips_id = x.lastrowid
            for cert_name, cert_type in cert_names.iteritems():
                x.execute("""INSERT INTO cert_names (cips_id, name, type, exp_date) VALUES({0}, "{1}", "{2}", "{3}")""".format(cips_id, cert_name, cert_type, exp_date))
            conn.commit()
        except Exception as sqle:
            conn.rollback()
    except Exception as ex:  # Catch all crashes.
        # Always save the IP
        x = conn.cursor()
        try:
           x.execute("""INSERT INTO checked_ips (ipstr, ip) VALUES("{0}", INET_ATON("{0}"))""".format(ip))
           conn.commit()
        except Exception as sqle:
           conn.rollback()

        #eno = ex.errno
        #if not eno in [errno.ECONNREFUSED, errno.ECONNRESET, 61, None]:  # 61 is socket.timeout
        #    raise serr
    finally:
        q.put(conn)
        return {ip: cert_names}


qlock = threading.Lock()
q = None
port = None
connect_timeout = None

if __name__ == "__main__":
    t0 = time.time()

    parser = argparse.ArgumentParser(description='Query IP for identifying SSL certificates.')
    parser.add_argument('-s', '--start', required=True, help='The starting IP address.')
    parser.add_argument('-e', '--end', required=True, help='The ending IP address.')
    parser.add_argument('-p', '--port', type=int, default=443, help="The port to test for the SSL certificate on.")
    parser.add_argument('-c', '--connect_to', type=int, default=2, help="How long to wait for the connection to the IP to timeout.")
    parser.add_argument('-t', '--threadpool', type=int, default=16, help="The threadpool size used to scan the IP range.")
    parser.add_argument('-a', '--aggregate', action='store_true', default=False, help="Should we aggregate and dump the results.")
    args = parser.parse_args()

    # Set the connect timeout
    connect_timeout = args.connect_to

    # Set the port to scan
    port = args.port

    # Create a Queue of usable connections
    q = Queue.Queue(args.threadpool)
    for i in range(args.threadpool):
        q.put(MySQLdb.connect(host="localhost", user="certscanner", passwd="Y0uSh0uldCh@ng3This!", db="cert_scanner"))

    # Define the threadpool
    pool = ThreadPool(args.threadpool)

    # Tell pool to process ips in function.

    ip_blk = ips(args.start, args.end)
    print("SCANNING: {0} - {1}".format(ip_blk['range'][0], ip_blk['range'][-1]))
    #print("    NEXT: {0} - {1}".format(ip_blk['next']['start'], ip_blk['next']['end']))
    if args.aggregate:
        results = pool.map(scan, ip_blk['range'])
        print(json.dumps(results))
    else:
        pool.map(scan, ip_blk['range'])

    while ip_blk['next']['start'] != -1:
        ip_blk = ips(ip_blk['next']['start'], ip_blk['next']['end'])
        print("SCANNING: {0} - {1}".format(ip_blk['range'][0], ip_blk['range'][-1]))
        #print("    NEXT: {0} - {1}".format(ip_blk['next']['start'], ip_blk['next']['end']))
        if args.aggregate:
            results = pool.map(scan, ip_blk['range'])
            print(json.dumps(results))
        else:
            pool.map(scan, ip_blk['range'])

    pool.close()
    pool.join()
    
    t1 = time.time()
    total = t1-t0
    print("Time: ", total)

    # Close DB connections.
    while not q.empty():
        conn = q.get()
        conn.close()
