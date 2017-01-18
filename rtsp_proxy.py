#!/usr/bin/env python2

import argparse
import asyncore
import asynchat
import subprocess
import os
import socket
import struct
import binascii
import re

class AuthPool(object):
    """This class runs svtool.py to get an auth token for a given
    username/password combo. It will hold the underlying svtool.py open until
    the last proxy using it disconnects.
    """

    def __init__(self, url):
        self.url = url

        self.svtool_path = os.path.join(os.path.dirname(__file__), 'svtool.py')

        self.creds2reqs = {}
        self.creds2sub = {}
        self.creds2token = {}

    def get_token(self, requester, username, password):
        self._flush()
        self._remove_requester(requester)

        creds = (username, password)

        self.creds2reqs.setdefault(creds, []).append(requester)

        if creds in self.creds2token:
            return self.creds2token[creds]

        env = os.environ.copy()
        env.update({'SV_USER': username, 'SV_PASS': password})
        sub = self.creds2sub[creds] = subprocess.Popen([self.svtool_path, self.url, 'authorize'], env=env, stdout=subprocess.PIPE)

        token = self.creds2token[creds] = sub.stdout.readline().strip()
        if token:
            return token

    def release(self, requester):
        self._remove_requester(requester)
        self._flush()

    def _remove_requester(self, requester):
        for reqs in self.creds2reqs.values():
            if requester in reqs: reqs.remove(requester)

    def _flush(self):
        for k,v in self.creds2reqs.items():
            if not v: del self.creds2reqs[k]

        for k,v in self.creds2sub.items():
            if k not in self.creds2reqs:
                try: v.terminate()
                except OSError: pass

                del self.creds2sub[k]
            elif v.poll() is not None:
                del self.creds2sub[k]

        for creds in self.creds2token.keys():
            if creds not in self.creds2sub:
                del self.creds2token[creds]

class RTSPChat(asynchat.async_chat):
    """This is an asynchat class for chatting with an RTSP server/client.

    RTSP messages follow the same general format as HTTP, where the headers are
    sent with CRLF line endings, a blank line is sent, and then a number of
    (optional) content bytes follow. Both requests and responses use this
    format, and this class is general enough to handle both.

    Subclasses should override got_message(headers, content) to handle a list
    of headers (one list item per line) and the content string ('' if absent)

    To send the same to the other end, use send_message()
    """

    def __init__(self, sock):
        asynchat.async_chat.__init__(self, sock=sock)

        self.__buffer = ''
        self.read_message()

    # Subclass should override:
    def got_message(self, headers, content):
        pass

    def got_interleaved(self, channel, data):
        pass

    # Send a message to the remote end of the socket:
    def send_message(self, headers, content):
        payload = '\r\n'.join(headers + ['', content])
        self.send(payload)

    def send_interleaved(self, channel, data):
        payload = struct.pack('>cBH', '$', channel, len(data)) + data
        self.send(payload)

    # Logic for line-based reading:
    def read_message(self):
        self.__reading_headers = True
        self.__reading_interleaved = False
        self.__headers = []
        self.__buffer = ''
        self.set_terminator('\r\n')

    def handle_line(self, line):
        if line:
            self.__headers.append(line)

            # HACK HACK HACK HACK HACK
            # Samsung's RTSP server doesn't do \r\n\r\n at the end of a SETUP
            # response (D'oh!!) so we have to be really crafty about
            # recognizing it ourselves.
            if self.__headers[0].startswith('RTSP/1.') and line.startswith('Transport: '):
                # Yep, this is the end of a SETUP response.
                self.read_content()

        elif self.__headers:
            self.read_content()

    # Logic for reading content:
    def read_content(self):
        self.__reading_headers = False
        length = self.find_content_length()
        if length:
            self.set_terminator(length)
        else:
            self.got_message(self.__headers, '')
            self.read_message()

    def find_content_length(self):
        for header in self.__headers:
            if header.lower().startswith('content-length: '):
                return int(header.split(': ',1)[1])
        else:
            return 0

    # Interleaved handler:
    def read_interleaved(self):
        self.__reading_interleaved = True
        self.__reading_headers = False

        total_size = 4
        if len(self.__buffer) >= 4:
            length, = struct.unpack('>xxH', self.__buffer[:4])
            total_size += length

        self.set_terminator(total_size - len(self.__buffer))
        if total_size == len(self.__buffer):
            self.found_terminator()

    def handle_interleaved(self, data):
        assert data.startswith('$')
        length, = struct.unpack('>xxH', data[:4])
        assert len(data) == length+4

        self.got_interleaved(ord(data[1]), data[4:])
        self.read_message()

    # asynchat handlers:
    def collect_incoming_data(self, data):
        self.__buffer += data

        if self.__reading_headers and self.__buffer.startswith('$'):
            # Interleaved data!
            self.read_interleaved()

    def found_terminator(self):
        if self.__reading_interleaved:
            self.handle_interleaved(self.__buffer)
        elif self.__reading_headers:
            self.handle_line(self.__buffer)
        else:
            self.got_message(self.__headers, self.__buffer)
            self.read_message()
        self.__buffer = ''

class RTPRelay(object):
    """Shared base class for the below.

    This defragments Samsung's weird RTP format."""
    def __init__(self, rtsp, channel):
        self.rtsp = rtsp
        self.channel = channel

        self.buffer = ''
        self.defragmented = None

    def handle_bytes(self, data):
        self.buffer += data

        while self.process_packet(): pass

    def process_packet(self):
        # Process one packet from self.buffer, returning True on success

        if len(self.buffer) < 12: return False # Not big enough to contain header

        hdr1, hdr2, seq, ts, ssrc = struct.unpack('>BBHII', self.buffer[:12])

        version = hdr1>>6
        extension_bit = hdr1&0x10
        csrc_count = hdr1&0x0F
        marker_bit = hdr2&0x80

        if version != 2:
            print 'Warning: Bad RTP packet version found. Resetting defragmenter.'
            self.buffer = ''
            self.defragmented = None
            return False

        if extension_bit:
            extension_offset = 12+4*csrc_count
            profile, ehdr_length = struct.unpack('>HH', self.buffer[extension_offset:][:4])
            extensions = self.buffer[extension_offset+4:][:ehdr_length*4]
            payload_offset = extension_offset+4+ehdr_length*4
        else:
            # We need this to determine length!
            print 'Warning: RTP packet with no extension header. Resetting defragmenter.'
            self.buffer = ''
            self.defragmented = None
            return False

        # Stop here if we still need more packet
        if len(self.buffer) < payload_offset: return False
        payload_len, = struct.unpack('<I', extensions[:4])
        if len(self.buffer) < payload_offset+payload_len: return False

        # See if this is a fresh packet, and if so, initialize the RTP header:
        if self.defragmented is None:
            self.defragmented = struct.pack('>BBHII', 0x80, hdr2, seq, ts, ssrc)

        if self.defragmented is not None:
            self.defragmented += self.buffer[payload_offset:][:payload_len]

        if marker_bit:
            self.pass_packet()

        self.buffer = self.buffer[payload_offset+payload_len:]
        return True

    def pass_packet(self):
        if self.defragmented is not None:
            self.rtsp.send_interleaved(self.channel, self.defragmented)
            self.defragmented = None

class RTPTCPRelay(asyncore.dispatcher, RTPRelay):
    """This connects to the RTP port and relays it as interleaved messages on
    the RTSP connection instead.
    """
    def __init__(self, rtsp, channel, endpoint, session):
        asyncore.dispatcher.__init__(self, sock=socket.create_connection(endpoint))
        RTPRelay.__init__(self, rtsp, channel)

        self.send(session + '\0')

    def handle_read(self):
        data = self.recv(0x10000)
        self.handle_bytes(data)

    def writable(self):
        return False

class RTPUDPRelay(asyncore.dispatcher, RTPRelay):
    """This communicates with the RTP UDP port and relays packets as interleaved
    messages on the RTSP connection instead.
    """
    def __init__(self, rtsp, channel, endpoint):
        asyncore.dispatcher.__init__(self)
        RTPRelay.__init__(self, rtsp, channel)

        self.create_socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.set_reuse_addr()

        self.sendto('\0', endpoint)

    def handle_read(self):
        data = self.recv(0x10000)
        if data != '\0':
            self.handle_bytes(data)

    def writable(self):
        return False

class ProxyHandler(RTSPChat):
    """This handles a proxied connection. It subclasses RTSPChat for the *local*
    (i.e. client-side) communication, and instantiates RTSPChat for the *remote*
    (i.e. server-side) end of the connection.

    RTSP requests may be "pipelined", where the client sends a bunch of them
    with differing CSeq headers and expects the server to send its responses
    with matching CSeq values. Samsung DVRs have been observed not to match the
    CSeq values, so we have to fix them for the client, and that means
    identifying RTSP responses by only allowing one pending request at a time.

    RTSP request<->response pairs are fixed up before going down to the client.
    """


    def __init__(self, sock, remote, auth_pool):
        RTSPChat.__init__(self, sock)

        self.got_message = self.got_request

        self.upstream = RTSPChat(remote)
        self.upstream.got_message = self.got_response
        self.upstream.handle_close = self.handle_close

        self.remote_ip, self.remote_port = remote.getpeername()

        self.auth_pool = auth_pool

        self.waiting_for_response = False
        self.pending_requests = []

        self.is_tcp = False # Set by DESCRIBE response

        self.relays = []

    def fixup_request(self):
        # This function fixes up self.request, returning True if it should be
        # sent or False otherwise.
        headers, content = self.request

        # First handle OPTIONS, which the Samsung DVRs do not implement:
        if headers[0].startswith('OPTIONS '):
            resp = ['RTSP/1.0 200 OK',
                    'Public: OPTIONS, DESCRIBE, SETUP, TEARDOWN, PLAY']
            cseq = self.get_header(headers, 'CSeq')
            if cseq is not None: resp.append(cseq)
            self.send_message(resp, '')
            return False

        # Make sure this matches a live.### URL. The DVR can crash(!) if not:
        split = headers[0].split(' ')
        self.url = split[1] if len(split) > 1 else ''
        if not re.match(r'.*/live.[0-9]{3}$', self.url):
            resp = ['RTSP/1.0 404 Not Found']
            cseq = self.get_header(headers, 'CSeq')
            if cseq is not None: resp.append(cseq)
            self.send_message(resp, '')
            return False

        # There MUST be an authorization. Error out if not:
        auth = self.get_auth_token()
        if not auth:
            resp = ['RTSP/1.0 401 Unauthorized',
                    'WWW-Authenticate: Basic realm="shrdvr"']
            cseq = self.get_header(headers, 'CSeq')
            if cseq is not None: resp.append(cseq)
            self.send_message(resp, '')
            return False
        else:
            self.set_header(headers, 'Authorization: ' + auth)

        if headers[0].startswith('SETUP '):
            # SETUP can deadlock the RTSP server if certain concerns aren't met

            # Depending on whether the server's running in TCP or UDP mode,
            # update the Transport: header.
            self.req_transport = self.get_header(headers, 'Transport')
            if self.is_tcp:
                self.set_header(headers, 'Transport: RTP/AVP/TCP;unicast')
            else:
                self.set_header(headers, 'Transport: RTP/AVP/UDP;unicast;client_port=12345')

            # The headers must be in this very particular order, and no other
            # headers may exist:
            order = ['SETUP', 'CSeq:', 'Transport:', 'Authorization:']
            headers = self.reorder_headers(headers, order)

            # And ALL headers must be present:
            if len(headers) != len(order):
                resp = ['RTSP/1.0 400 Bad Request']
                cseq = self.get_header(headers, 'CSeq')
                if cseq is not None: resp.append(cseq)
                self.send_message(resp, '')
                return False

            self.request = headers, content

        if headers[0].startswith('PLAY '):
            # PLAY is similarly particular:
            self.set_header(headers, 'Range: npt=0.000-')
            self.set_header(headers, 'Speed: +1.0')
            self.set_header(headers, 'Bandwidth: 2048')

            order = ['PLAY', 'CSeq:', 'Session:', 'Range:', 'Speed:',
                     'Bandwidth:', 'Authorization:']
            headers = self.reorder_headers(headers, order)

            if len(headers) != len(order):
                resp = ['RTSP/1.0 400 Bad Request']
                cseq = self.get_header(headers, 'CSeq')
                if cseq is not None: resp.append(cseq)
                self.send_message(resp, '')
                return False

            self.request = headers, content

        return True

    def fixup_response(self):
        req_headers, req_content = self.request
        resp_headers, resp_content = self.response

        # If the request had a CSeq, make sure we have the same:
        cseq = self.get_header(req_headers, 'CSeq')
        if cseq:
            self.set_header(resp_headers, cseq)

        if req_headers[0].startswith('DESCRIBE '):
            ctype = self.get_header(resp_headers, 'Content-Type')
            if ctype is not None and ctype.endswith('text/parameters'):
                self.set_header(resp_headers, 'Content-Type: application/sdp')
                resp_content = self.fixup_sdp(resp_content)
                self.set_header(resp_headers, 'Content-Length: ' + str(len(resp_content)))

        if req_headers[0].startswith('SETUP '):
            # Client expects interleaved RTP data, but the DVR provides it on a
            # separate port. Connect to that port with an RTP relay:
            transport = self.get_header(resp_headers, 'Transport')
            port_match = re.search(r'server_port=([0-9]+)', transport)
            interleave_match = re.search(r'interleaved=([0-9]+)(-[0-9]+)?', self.req_transport)

            if not interleave_match:
                channel = 0
                interleaved_header = 'interleaved=0'
            else:
                channel = int(interleave_match.group(1))
                interleaved_header = interleave_match.group(0)

            self.set_header(resp_headers, 'Transport: RTP/AVP/TCP;unicast;' + interleaved_header)

            port = int(port_match.group(1)) if port_match else self.remote_port+2

            session = self.get_header(resp_headers, 'Session')

            if self.is_tcp:
                relay = RTPTCPRelay(self, channel, (self.remote_ip, port), session)
            else:
                relay = RTPUDPRelay(self, channel, (self.remote_ip, port))
            self.relays.append(relay)

        self.response = (resp_headers, resp_content)

        return True

    def fixup_sdp(self, sdp):
        # This function tries to fix an sdp document:
        lines = sdp.split('\r\n')
        for i,line in enumerate(lines):
            if line.startswith('m='):
                match = re.match(r'm=video 0 (TCP )?RTP/AVP ([0-9]+) H.264', line)
                if not match: continue

                self.is_tcp = bool(match.group(1))

                profile = match.group(2)
                lines.insert(i+1, 'a=control:{}'.format(self.url))
                lines.insert(i+1, 'a=rtpmap:{} H264/1000'.format(profile))

                lines[i] = 'm=video 0 RTP/AVP {}'.format(profile)

        return '\r\n'.join(lines)

    def get_auth_token(self):
        # This tries to get a Samsung-style Authorization header from the DCP
        # service, using the username/password specified in the request's
        # Authorization header.

        headers, content = self.request
        auth_header = self.get_header(headers, 'Authorization')
        if auth_header is None: return None # Can't proceed without user/pass

        # Split and unbase64 the auth header:
        split = auth_header.split()
        if len(split) != 3: return None
        if split[1] != 'Basic': return None
        try:
            user_pass = binascii.a2b_base64(split[2])
        except binascii.Error:
            return None

        username, _, password = user_pass.partition(':')
        if _ != ':': return None

        return self.auth_pool.get_token(self, username, password)

    # Utility functions for handling headers:
    @staticmethod
    def set_header(headers, new):
        """Inject `new` into `headers`, replacing the existing matching header
        if one is already present.
        """

        new_prefix = new.lower().partition(': ')[0] + ': '

        for i, header in enumerate(headers):
            if header.lower().startswith(new_prefix):
                headers.pop(i)
                headers.insert(i, new)
                return
        else:
            headers.append(new)

    @staticmethod
    def get_header(headers, search):
        """Search for a `search` header in the `headers` list."""

        prefix = search.lower() + ': '

        for header in headers:
            if header.lower().startswith(prefix):
                return header

    @staticmethod
    def reorder_headers(headers, order):
        headers = filter(lambda x: x.partition(' ')[0] in order, headers)
        headers.sort(key=lambda x: order.index(x.partition(' ')[0]))
        return headers

    # De-pipelining behavior:
    def got_request(self, headers, content):
        self.pending_requests.append((headers, content))
        self.flush_requests()

    def flush_requests(self):
        if self.waiting_for_response: return # Already sent a request to the server
        if not self.pending_requests: return # Nothing TO send

        self.request = self.pending_requests.pop(0)
        if self.fixup_request():
            self.upstream.send_message(*self.request)
            self.upstream.read_message() # Discard garbage
            self.waiting_for_response = True
        else:
            self.flush_requests()

    def got_response(self, headers, content):
        assert self.waiting_for_response

        self.response = (headers, content)
        if self.fixup_response():
            self.send_message(*self.response)

        self.waiting_for_response = False
        self.flush_requests()

    def handle_close(self):
        self.close()
        self.upstream.close()
        self.auth_pool.release(self)
        for relay in self.relays:
            relay.close()

class ProxyServer(asyncore.dispatcher):
    """This just listens on the proxy port and fires off a connection to the
    server whenever a connection is made.
    """

    def __init__(self, local, remote):
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind(local)
        self.listen(5)

        self.remote = remote

        self.auth_pool = AuthPool('rtsp://{}:{}/'.format(*remote))

    def handle_accept(self):
        pair = self.accept()
        if pair is None: return

        sock, addr = pair
        remote = socket.create_connection(self.remote)
        ProxyHandler(sock, remote, self.auth_pool)

parser = argparse.ArgumentParser(description='Sit between an RTSP client and a Samsung DVR')

parser.add_argument('local', help='Local IP:port pair')
parser.add_argument('remote', help='Remote IP:port pair')

if __name__ == '__main__':
    args = parser.parse_args()

    local_ip, _, local_port = args.local.partition(':')
    remote_ip, _, remote_port = args.remote.partition(':')

    ProxyServer((local_ip, int(local_port)), (remote_ip, int(remote_port)))
    asyncore.loop(use_poll=True)
