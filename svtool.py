#!/usr/bin/env python2

import socket
import struct
import hashlib
import binascii
import argparse
import urlparse
import os
import sys
import time

# No idea where this comes from, but usernames are XORed against it:
USERNAME_XOR = bytearray(binascii.unhexlify('70b3366ac0a375aa1d6b8469d3ae4ab1'))
SV_HEADER = 0x00005653

class AuthenticationError(Exception): pass
class SVConnection(object):
    def __init__(self, socket, username=None, password=None):
        self.s = socket

        if username is not None and password is not None:
            auth_result = self.authenticate(username, password)
            if auth_result != 'SUCCESS': raise AuthenticationError(auth_result)

    def send_sv(self, msg, payload=''):
        # Pad message-type to 25 bytes:
        msg += b'\0' * (25-len(msg))

        # Determine payload type:
        if type(payload) == bytes:
            ptype = b'\x01BINARY\0\0\0\0'
        else:
            ptype = b'\x01TEXT\0\0\0\0\0\0'
            payload = payload.encode('utf8')
        total_len = len(msg + ptype + payload) + 8

        sv = struct.pack('<II', SV_HEADER, total_len) + msg + ptype + payload
        self.s.send(sv)

    def recv_sv(self):
        buf = b''

        # Receive just enough to determine total length:
        while len(buf) < 8:
            d = self.s.recv(8 - len(buf))
            if not d: raise EOFError()
            buf += d

        sv_header, total_len = struct.unpack('<II', buf)
        assert sv_header == SV_HEADER

        while len(buf) < total_len:
            d = self.s.recv(total_len - len(buf))
            if not d: raise EOFError()
            buf += d

        msg = buf[8:].split(b'\0',1)[0]
        ptype = buf[0x22:].split(b'\0',1)[0]
        payload = buf[0x2c:].split(b'\0',1)[0]

        if ptype == b'TEXT':
            payload = payload.decode('latin1')

        return (msg, payload)

    def authenticate(self, username, password):
        # XOR encode username:
        assert len(username) <= len(USERNAME_XOR)
        username_enc = bytearray(username.encode('utf8'))
        for i,_ in enumerate(username_enc): username_enc[i] ^= USERNAME_XOR[i]
        username_b64 = binascii.b2a_base64(username_enc).strip().decode('ascii')

        # MD5-hash password:
        password_hash = hashlib.md5(password.encode('utf8')).hexdigest()

        # Format payload:
        payload = u'ID:{}\r\nPW:{}\r\n'.format(username_b64, password_hash)

        self.send_sv(b'AUTHENTICATE', payload)

        auth_ok, status = self.recv_sv()

        assert auth_ok == b'AUTHENTICATE_OK'
        return status.strip('\r\n\0')
    
    def describe(self):
        self.send_sv(b'DESCRIBE')
        describe_ok, describe = self.recv_sv()

        assert describe_ok == b'DESCRIBE_OK'
        
        description = {}
        for line in describe.splitlines():
            k,_,v = line.partition(':')
            description[k] = v
        return description
    
    def heartbeat(self):
        self.send_sv(b'HEARTBEAT')
        heartbeat_ok, heartbeat = self.recv_sv()

        assert heartbeat_ok == b'HEARTBEAT'

parser = argparse.ArgumentParser(description='Connect to a Samsung SmartViewer-based DVR.')
parser.add_argument('url', type=urlparse.urlparse, help='RTSP URL of the DVR')
parser.add_argument('--username', default=None, help='Override username in RTSP URL (if both absent, SV_USER environment variable used)')
parser.add_argument('--password', default=None, help='Override password in RTSP URL (if both absent, SV_PASS environment variable used)')

sp = parser.add_subparsers()


def do_describe(sv, args):
    for k,v in sv.describe().items():
        sys.stdout.write('{}: {}\n'.format(k, v))
    sys.stdout.flush()

describe = sp.add_parser('describe')
describe.set_defaults(func=do_describe)

def do_authorize(sv, args):
    sys.stdout.write(sv.describe()['authority'] + '\n')
    sys.stdout.flush()

    if args.duration:
        disconnect = time.time() + args.duration
    else:
        disconnect = None

    while disconnect is None or disconnect > time.time():
        time.sleep(args.heartbeat_interval)
        sv.heartbeat()
authorize = sp.add_parser('authorize')
authorize.set_defaults(func=do_authorize)
authorize.add_argument('--duration', default=0, type=int, help='How long to remain connected (and therefore keep the authorization valid')
authorize.add_argument('--heartbeat-interval', default=10, type=int, help='How often to send heartbeats to keep the connection active')

if __name__ == '__main__':
    args = parser.parse_args()

    host = args.url.hostname
    port = args.url.port or 554
    port += 1 # SmartViewer protocol runs on DCP port, which is always 1 above RTSP

    username = args.username or args.url.username
    password = args.password or args.url.password
    
    if username is None:
        username = os.environ['SV_USER']
    if password is None:
        password = os.environ['SV_PASS']

    sv = SVConnection(socket.create_connection((host, port)), username, password)
    args.func(sv, args)
