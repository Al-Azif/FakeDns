#!/usr/bin/python3
# -*- coding: utf-8 -*-
""" FakeDns by Crypt0s, Fork by Al-Azif
   Source: https://github.com/Al-Azif/FakeDns
"""

import codecs
import os
import re
import socketserver
import socket
import sys
import threading


class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    daemon_threads = True
    allow_resuse_address = True

    def __init__(self, server_address, request_handler):
        self.address_family = socket.AF_INET
        socketserver.UDPServer.__init__(self, server_address, request_handler)


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        (data, s) = self.request
        p = DNSQuery(data)
        response = rules.match(p, self.client_address[0])
        s.sendto(response, self.client_address)


class DNSQuery:
    def __init__(self, data):
        self.data = data
        self.domain = ''
        tipo = (data[2] >> 3) & 15
        if tipo == 0:
            ini = 12
            lon = data[ini]
            while lon != 0:
                self.domain += '{}.'.format(codecs.decode(data[ini + 1:ini + lon + 1], 'utf-8'))
                ini += lon + 1
                lon = data[ini]
            self.type = data[ini:][1:3]
        else:
            self.type = data[-4:-2]


class DNSResponse(object):
    def __init__(self, query):
        self.id = query.data[:2]
        self.flags = b'\x81\x80'
        self.questions = query.data[4:6]
        self.rranswers = b'\x00\x01'
        self.rrauthority = b'\x00\x00'
        self.rradditional = b'\x00\x00'
        self.query = self.get_question_section(query)
        self.pointer = b'\xc0\x0c'
        self.type = None
        self.dnsclass = b'\x00\x01'
        self.ttl = b'\x00\x00\x00\x01'
        self.length = None
        self.data = None

    @staticmethod
    def get_question_section(query):
        start_idx = 12
        end_idx = start_idx
        num_questions = (query.data[4] << 8) | query.data[5]

        while num_questions > 0:
            while query.data[end_idx] != 0:
                end_idx += query.data[end_idx] + 1
            end_idx += 5
            num_questions -= 1

        return query.data[start_idx:end_idx]

    def make_packet(self):
        try:
            return self.id + self.flags + self.questions + self.rranswers + \
                self.rrauthority + self.rradditional + self.query + \
                self.pointer + self.type + self.dnsclass + self.ttl + \
                self.length + self.data
        except (TypeError, ValueError):
            pass


class A(DNSResponse):
    def __init__(self, query, record):
        super(A, self).__init__(query)
        self.type = b'\x00\x01'
        self.length = b'\x00\x04'
        self.data = self.get_ip(record)

    @staticmethod
    def get_ip(dns_record):
        return b''.join(map(lambda x: bytes([int(x)]), dns_record.split('.')))


class AAAA(DNSResponse):
    def __init__(self, query, address):
        super(AAAA, self).__init__(query)
        self.type = b'\x00\x1c'
        self.length = b'\x00\x10'
        self.data = address

    @staticmethod
    def get_ip_6(host, port=0):
        result = socket.getaddrinfo(host, port, socket.AF_INET6)
        ip = result[0][4][0]
        return ip


class CNAME(DNSResponse):
    def __init__(self, query):
        super(CNAME, self).__init__(query)
        self.type = b'\x00\x05'


class PTR(DNSResponse):
    def __init__(self, query, ptr_entry):
        super(PTR, self).__init__(query)
        self.type = b'\x00\x0c'
        self.ttl = b'\x00\x00\x00\x00'
        ptr_split = ptr_entry.split('.')
        ptr_entry = b'\x07'.join(ptr_split)
        self.data = b'\x09{}\x00'.format(ptr_entry)
        self.length = chr(len(ptr_entry) + 2)
        if self.length < b'\xff':
            self.length = b'\x00{}'.format(self.length)


class TXT(DNSResponse):
    def __init__(self, query, txt_record):
        super(TXT, self).__init__(query)
        self.type = b'\x00\x10'
        self.data = txt_record
        self.length = chr(len(txt_record) + 1)
        if self.length < b'\xff':
            self.length = b'\x00{}'.format(self.length)
        self.length += chr(len(txt_record))


class NONEFOUND(DNSResponse):
    def __init__(self, query):
        super(NONEFOUND, self).__init__(query)
        self.type = query.type
        self.flags = b'\x81\x83'
        self.rranswers = b'\x00\x00'
        self.length = b'\x00\x00'
        self.data = b'\x00'
        if DEBUG:
            print('>> Built NONEFOUND response')


class Rule(object):
    def __init__(self, rule_type, domain, ip):
        self.type = rule_type
        self.domain = domain
        self.ip = ip

    def match(self, req_type, domain, addr):
        try:
            req_type = TYPE[req_type]
        except KeyError:
            return None

        try:
            assert self.type == req_type
        except AssertionError:
            return None

        try:
            assert self.domain.match(domain)
        except AssertionError:
            return None

        return self.ip


class RuleError_BadRegularExpression(Exception):
    def __init__(self, lineno):
        if DEBUG:
            print('>> Malformed Regular Expression on rulefile line #{}'.format(lineno))


class RuleError_BadRuleType(Exception):
    def __init__(self, lineno):
        if DEBUG:
            print('>> Rule type unsupported on rulefile line #{}'.format(lineno))


class RuleError_BadFormat(Exception):
    def __init__(self, lineno):
        if DEBUG:
            print('>> Not Enough Parameters for rule on rulefile line #{}'.format(lineno))


class RuleEngine:
    def __init__(self, rules):
        self.match_history = {}
        self.rule_list = []

        lineno = 0

        for rule in rules:
            if len(rule.strip()) == 0 or rule == '\n':
                continue

            if len(rule.split()) < 3:
                raise RuleError_BadFormat(lineno)

            s_rule = rule.split()
            rule_type = s_rule[0].upper()
            domain = s_rule[1]
            ip = s_rule[2]

            if rule_type not in list(TYPE.values()):
                raise RuleError_BadRuleType(lineno)
            try:
                domain = re.compile(domain)
            except re.error:
                raise RuleError_BadRegularExpression(lineno)

            if rule_type.upper() == 'AAAA':
                if self.__is_shorthand_ip(ip):
                    ip = self.__explode_shorthand_ip_string(ip)
                ip = ip.replace(':', '').decode('hex')

            self.rule_list.append(Rule(rule_type, domain, ip))

            lineno += 1

        if DEBUG:
            print('>> FakeDns parsed {} rules'.format(len(self.rule_list)))

    def __is_shorthand_ip(self, ip_str):
        if ip_str.count('::') == 1:
            return True
        if any(len(x) < 4 for x in ip_str.split(':')):
            return True
        return False

    def __explode_shorthand_ip_string(self, ip_str):
        if not self.__is_shorthand_ip(ip_str):
            return ip_str

        hextet = ip_str.split('::')

        if '.' in ip_str.split(':')[-1]:
            fill_to = 7
        else:
            fill_to = 8

        if len(hextet) > 1:
            sep = len(hextet[0].split(':')) + len(hextet[1].split(':'))
            new_ip = hextet[0].split(':')

            for _ in range(fill_to - sep):
                new_ip.append('0000')
            new_ip += hextet[1].split(':')

        else:
            new_ip = ip_str.split(':')

        ret_ip = []
        for hextet in new_ip:
            ret_ip.append(('0' * (4 - len(hextet)) + hextet).lower())
        return ':'.join(ret_ip)

    def match(self, query, addr):
        if addr not in IGNORE:
            for rule in self.rule_list:
                result = rule.match(query.type, query.domain, addr)
                if result is not None:
                    response_data = result

                    if response_data.lower() == 'none':
                        return NONEFOUND(query).make_packet()

                    response = CASE[query.type](query, response_data)

                    if DEBUG:
                        print('>> Matched Request: {}'.format(query.domain))
                    return response.make_packet()
        else:
            passthru = True
            print('>> Pass-thru for {}: {}'.format(addr, query.domain))

        try:
            s = socket.socket(type=socket.SOCK_DGRAM)
            s.settimeout(3.0)
            addr = ('{}'.format('8.8.8.8'), PORT_DNS)
            s.sendto(query.data, addr)
            data = s.recv(1024)
            s.close()
            if DEBUG and not passthru:
                print('>> Unmatched Request: {}'.format(query.domain))
            return data
        except socket.error:
            if DEBUG:
                print('>> Error was handled by sending NONEFOUND')
            return NONEFOUND(query).make_packet()


def getch():
    """MIT Licensed: https://github.com/joeyespo/py-getch"""
    import termios
    import tty

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        return sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def closer(message):
    """Closing method"""
    print(message)
    if message != '\r>> Exiting...                                           ':
        print('Press any key to exit...', end='')
        sys.stdout.flush()
        if os.name == 'nt':
            from msvcrt import getch as w_getch
            w_getch()
        else:
            getch()
        print()
    sys.exit()

def main(interface, rule_array, ignore, debug, port_dns):
    global rule_list
    global rules
    global TYPE
    global CASE
    global DEBUG
    global IGNORE
    global PORT_DNS

    DEBUG = bool(debug)

    if not (port_dns is None):
        PORT_DNS = port_dns
    else:
        PORT_DNS = 53

    TYPE = {
        b'\x00\x01': 'A',
        b'\x00\x1c': 'AAAA',
        b'\x00\x05': 'CNAME',
        b'\x00\x0c': 'PTR',
        b'\x00\x10': 'TXT',
        b'\x00\x0f': 'MX',
        b'\x00\x06': 'SOA'
    }

    CASE = {
        b'\x00\x01': A,
        b'\x00\x1c': AAAA,
        b'\x00\x05': CNAME,
        b'\x00\x0c': PTR,
        b'\x00\x10': TXT
    }

    IGNORE = ignore

    rules = RuleEngine(rule_array)
    rule_list = rules.rule_list

    try:
        server = ThreadedUDPServer((interface, PORT_DNS), UDPHandler)
    except socket.error:
        closer('ERROR: Could not start server, is another program on udp:{}?'.format(PORT_DNS))
    except OSError:
        print('ERROR: Could not start server, is another program on udp:{}'.format(PORT_DNS))
        closer('    ^^This could also be a permission error^^')

    thread = threading.Thread(name='DNS_Server',
                              target=server.serve_forever,
                              args=(),
                              daemon=True)
    thread.start()


if __name__ == '__main__':
    pass
