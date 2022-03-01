from datetime import datetime
from sipfullproxy import UDPHandler
import socketserver
import socket
import logging
import time
import sys

HOST, PORT = '0.0.0.0', 5060


def main():
    log_format = input('if you want a new log file, press y,\n'
                       'if you want the log to go to the general log, press any other button\n')
    log_file = 'communication_' + datetime.now().strftime("%Y%m%d_%H-%M-%S") + '.log' \
        if log_format == 'y' else 'communication.log'

    logging.basicConfig(filename=log_file, format='%(asctime)s - %(levelname)s - %(message)s',
                        datefmt='%H:%M:%S', level=logging.INFO)

    logging.info(time.strftime("%a, %d %b %Y %H:%M:%S ", time.localtime()))
    hostname = socket.gethostname()
    logging.info(hostname)

    ipaddress = input('enter the ip of the proxy: ')

    # ipaddress = socket.gethostbyname(hostname)
    if ipaddress == '127.0.0.1':
        ipaddress = sys.argv[1]
    logging.info(ipaddress)

    print('connection is established at:\n[hostname] ' + hostname + '\n[ip] ' + ipaddress)

    recordroute = "Record-Route: <sip:%s:%d;lr>" % (ipaddress, PORT)
    topvia = "Via: SIP/2.0/UDP %s:%d" % (ipaddress, PORT)

    server = socketserver.UDPServer((HOST, PORT), UDPHandler)
    server.serve_forever()


if __name__ == '__main__':
    main()
