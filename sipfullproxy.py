#    Copyright 2014 Philippe THIRION
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.


import socketserver
import re
import time
import logging

HOST, PORT = '0.0.0.0', 5060

rx_register = re.compile("^REGISTER")
rx_invite = re.compile("^INVITE")
rx_ack = re.compile("^ACK")
rx_prack = re.compile("^PRACK")
rx_cancel = re.compile("^CANCEL")
rx_bye = re.compile("^BYE")
rx_options = re.compile("^OPTIONS")
rx_subscribe = re.compile("^SUBSCRIBE")
rx_publish = re.compile("^PUBLISH")
rx_notify = re.compile("^NOTIFY")
rx_info = re.compile("^INFO")
rx_message = re.compile("^MESSAGE")
rx_refer = re.compile("^REFER")
rx_update = re.compile("^UPDATE")
rx_from = re.compile("^From:")
rx_cfrom = re.compile("^f:")
rx_to = re.compile("^To:")
rx_cto = re.compile("^t:")
rx_tag = re.compile(";tag")
rx_contact = re.compile("^Contact:")
rx_ccontact = re.compile("^m:")
rx_uri = re.compile("sip:([^@]*)@([^;>$]*)")
rx_addr = re.compile("sip:([^ ;>$]*)")
rx_code = re.compile("^SIP/2.0 ([^ ]*)")
# rx_invalid = re.compile("^192\.168")
rx_invalid = re.compile("^10\.")
rx_request_uri = re.compile("^([^ ]*) sip:([^ ]*) SIP/2.0")
rx_route = re.compile("^Route:")
rx_contentlength = re.compile("^Content-Length:")
rx_ccontentlength = re.compile("^l:")
rx_via = re.compile("^Via:")
rx_cvia = re.compile("^v:")
rx_branch = re.compile(";branch=([^;]*)")
rx_rport = re.compile(";rport$|;rport;")
rx_contact_expires = re.compile("expires=([^;$]*)")
rx_expires = re.compile("^Expires: (.*)$")

# global dictionary
recordroute = ""
topvia = ""
registrar = {}


def hexdump(chars, sep, width):
    while chars:
        line = chars[:width]
        chars = chars[width:]
        line = line.ljust(width, '\000')
        logging.debug("%s%s%s" % (sep.join("%02x" % ord(c) for c in line), sep, quotechars(line)))


def quotechars(chars):
    return ''.join(['.', c][c.isalnum()] for c in chars)


def showtime():
    logging.debug(time.strftime("(%H:%M:%S)", time.localtime()))


class UDPHandler(socketserver.BaseRequestHandler):

    def debug_register(self):
        logging.debug("*** REGISTRAR ***")
        logging.debug("*****************")
        for key in registrar.keys():
            logging.debug("%s -> %s" % (key, registrar[key][0]))
        logging.debug("*****************")

    def change_request_uri(self):
        # change request uri
        md = rx_request_uri.search(self.data[0])

        if md:
            method = md.group(1)
            uri = md.group(2)
            if uri in registrar:
                uri = "sip:%s" % registrar[uri][0]
                self.data[0] = "%s %s SIP/2.0" % (method, uri)

    def remove_route_header(self):
        # delete Route
        data = []
        for line in self.data:
            if not rx_route.search(line):
                data.append(line)
        return data

    def add_top_via(self):
        branch = ""
        data = []

        for line in self.data:
            if rx_via.search(line) or rx_cvia.search(line):
                md = rx_branch.search(line)
                if md:
                    branch = md.group(1)
                    via = "%s;branch=%sm" % (topvia, branch)
                    data.append(via)

                # rport processing
                if rx_rport.search(line):
                    text = "received=%s;rport=%d" % self.client_address
                    via = line.replace("rport", text)
                else:
                    text = "received=%s" % self.client_address[0]
                    via = "%s;%s" % (line, text)
                data.append(via)

            else:
                data.append(line)

        return data

    def remove_top_via(self):
        data = []

        for line in self.data:
            if rx_via.search(line) or rx_cvia.search(line):
                if not line.startswith(topvia):
                    data.append(line)
            else:
                data.append(line)

        return data

    def check_validity(self, uri):
        addrport, socket, client_addr, validity = registrar[uri]
        now = int(time.time())

        if validity > now:
            return True
        else:
            del registrar[uri]
            logging.warning("registration for %s has expired" % uri)
            return False

    def get_socket_info(self, uri):
        addrport, socket, client_addr, validity = registrar[uri]
        return socket, client_addr

    def get_destination(self):
        destination = ""
        for line in self.data:
            if rx_to.search(line) or rx_cto.search(line):
                md = rx_uri.search(line)
                if md:
                    destination = "%s@%s" % (md.group(1), md.group(2))
                break
        return destination

    def get_origin(self):
        origin = ""
        for line in self.data:
            if rx_from.search(line) or rx_cfrom.search(line):
                md = rx_uri.search(line)
                if md:
                    origin = "%s@%s" % (md.group(1), md.group(2))
                break
        return origin

    def send_response(self, code):
        request_uri = "SIP/2.0 " + code
        self.data[0] = request_uri
        index = 0
        data = []

        for line in self.data:
            data.append(line)
            if rx_to.search(line) or rx_cto.search(line):
                if not rx_tag.search(line):
                    data[index] = "%s%s" % (line, ";tag=123456")
            if rx_via.search(line) or rx_cvia.search(line):
                # rport processing
                if rx_rport.search(line):
                    text = "received=%s;rport=%d" % self.client_address
                    data[index] = line.replace("rport", text)
                else:
                    text = "received=%s" % self.client_address[0]
                    data[index] = "%s;%s" % (line, text)
            if rx_contentlength.search(line):
                data[index] = "Content-Length: 0"
            if rx_ccontentlength.search(line):
                data[index] = "l: 0"
            index += 1
            if line == "":
                break

        data.append("")
        text = '\r\n'.join(data)

        self.socket.sendto(text.encode(), self.client_address)
        showtime()
        logging.info("[ PROXY response ] --- %s" % data[0])
        logging.debug("---\n<< server send [%d]:\n%s\n---" % (len(text), text))

    def process_register(self):
        fromm = ""
        contact = ""
        contact_expires = ""
        header_expires = ""
        expires = 0
        validity = 0
        authorization = ""
        index = 0
        auth_index = 0
        data = []
        size = len(self.data)

        for line in self.data:
            if rx_to.search(line) or rx_cto.search(line):
                md = rx_uri.search(line)
                if md:
                    fromm = "%s@%s" % (md.group(1), md.group(2))

            if rx_contact.search(line) or rx_ccontact.search(line):
                md = rx_uri.search(line)
                if md:
                    contact = md.group(2)
                else:
                    md = rx_addr.search(line)
                    if md:
                        contact = md.group(1)
                md = rx_contact_expires.search(line)
                if md:
                    contact_expires = md.group(1)

            md = rx_expires.search(line)
            if md:
                header_expires = md.group(1)

        if len(contact_expires) > 0:
            expires = int(contact_expires)
        elif len(header_expires) > 0:
            expires = int(header_expires)

        if expires == 0:
            if fromm in registrar:
                del registrar[fromm]
                self.send_response("200 Everything Going Super Well")
                return
        else:
            now = int(time.time())
            validity = now + expires

        logging.info("[ CALLER response ] account: %s (located at %s)" % (fromm, contact))
        logging.debug("Client address: %s:%s" % self.client_address)
        logging.debug("Expires= %d" % expires)
        registrar[fromm] = [contact, self.socket, self.client_address, validity]
        self.debug_register()
        self.send_response("200 Everything Going Super Well")

    def process_invite(self):
        logging.debug("-----------------")
        logging.debug(" INVITE received ")
        logging.debug("-----------------")
        origin = self.get_origin()

        if len(origin) == 0 or origin not in registrar:
            self.send_response("400 Request Gone Wrong")
            return

        destination = self.get_destination()
        if len(destination) > 0:
            logging.info("[ recipient ] %s" % destination)
            if destination in registrar and self.check_validity(destination):
                socket, claddr = self.get_socket_info(destination)
                # self.change_request_uri()
                self.data = self.add_top_via()
                data = self.remove_route_header()
                # insert Record-Route
                data.insert(1, recordroute)
                text = '\r\n'.join(data)
                socket.sendto(text.encode(), claddr)
                showtime()
                logging.info("< msg < %s" % data[0])
                logging.debug("---\n<< server send [%d]:\n%s\n---" % (len(text), text))
            else:
                self.send_response("480 The Called Destination is Too Popular for You")
        else:
            self.send_response("500 Server In Crisis")

    def process_ack(self):
        logging.debug("--------------")
        logging.debug(" ACK received ")
        logging.debug("--------------")
        destination = self.get_destination()
        if len(destination) > 0:
            logging.info("[ recipient ] %s" % destination)
            if destination in registrar:
                socket, claddr = self.get_socket_info(destination)
                # self.change_request_uri()
                self.data = self.add_top_via()
                data = self.remove_route_header()
                # insert Record-Route
                data.insert(1, recordroute)
                text = '\r\n'.join(data)
                socket.sendto(text.encode(), claddr)  # todo: check for 'utf-8'
                showtime()
                logging.info("< msg < %s" % data[0])
                logging.debug("---\n<< server send [%d]:\n%s\n---" % (len(text), text))

    def process_non_invite(self):
        logging.debug("----------------------")
        logging.debug(" NonInvite received   ")
        logging.debug("----------------------")
        origin = self.get_origin()
        if len(origin) == 0 or origin not in registrar:
            self.send_response("400 Request Gone Wrong")
            return
        destination = self.get_destination()
        if len(destination) > 0:
            logging.info("[ recipient ] %s" % destination)
            if destination in registrar and self.check_validity(destination):
                socket, claddr = self.get_socket_info(destination)
                # self.change_request_uri()
                self.data = self.add_top_via()
                data = self.remove_route_header()
                # insert Record-Route
                data.insert(1, recordroute)
                text = '\r\n'.join(data)
                socket.sendto(text.encode(), claddr)  # todo: 'utf-8'
                showtime()
                logging.info("< msg < %s" % data[0])
                logging.debug("---\n<< server send [%d]:\n%s\n---" % (len(text), text))
            else:
                self.send_response("406 Think Again, Buddy")
        else:
            self.send_response("500 Server In Crisis")

    def process_code(self):
        origin = self.get_origin()
        if len(origin) > 0:
            logging.debug("origin %s" % origin)
            if origin in registrar:
                socket, claddr = self.get_socket_info(origin)
                self.data = self.remove_route_header()
                data = self.remove_top_via()
                text = '\r\n'.join(data)
                socket.sendto(text.encode(), claddr)  # todo: 'utf-8'
                showtime()
                logging.info("< msg < %s" % data[0])
                logging.debug("---\n<< server send [%d]:\n%s\n---" % (len(text), text))

    def process_request(self):
        # print "process_request"
        if len(self.data) > 0:
            request_uri = self.data[0]

            if rx_register.search(request_uri):
                self.process_register()
            elif rx_invite.search(request_uri):
                self.process_invite()
            elif rx_ack.search(request_uri):
                self.process_ack()

            elif rx_bye.search(request_uri):
                self.process_non_invite()
            elif rx_cancel.search(request_uri):
                self.process_non_invite()
            elif rx_options.search(request_uri):
                self.process_non_invite()
            elif rx_info.search(request_uri):
                self.process_non_invite()
            elif rx_message.search(request_uri):
                self.process_non_invite()
            elif rx_refer.search(request_uri):
                self.process_non_invite()
            elif rx_prack.search(request_uri):
                self.process_non_invite()
            elif rx_update.search(request_uri):
                self.process_non_invite()

            elif rx_subscribe.search(request_uri):
                self.send_response("200 Everything Going Super Well")
            elif rx_publish.search(request_uri):
                self.send_response("200 Everything Going Super Well")
            elif rx_notify.search(request_uri):
                self.send_response("200 Everything Going Super Well")

            elif rx_code.search(request_uri):
                self.process_code()
            else:
                logging.error("request_uri %s" % request_uri)
                # print ("message %s unknown" % self.data)

    def handle(self):
        # socket.setdefaulttimeout(120)
        data = self.request[0].decode()  # todo: 'utf-8'?
        self.data = data.split("\r\n")
        self.socket = self.request[1]
        request_uri = self.data[0]

        if rx_request_uri.search(request_uri) or rx_code.search(request_uri):
            showtime()
            logging.info("> request > %s" % request_uri)
            logging.debug("---\n>> server received [%d]:\n%s\n---" % (len(data), data))
            logging.debug("Received from %s:%d" % self.client_address)
            self.process_request()
        else:
            if len(data) > 4:
                showtime()
                logging.warning("---\n>> server received [%d]:" % len(data))
                hexdump(data, ' ', 16)
                logging.warning("---")
