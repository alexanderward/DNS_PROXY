import logging
import time
from SocketServer import BaseRequestHandler, ThreadingUDPServer
import socket

from scapy.layers.dns import DNS

from core.handle import process_packet, parse_packet, dns_opcodes
from core.types import DNSTypes


class Cache(object):
	cache = {}
	enabled = True

	def __generate_key(self, pkt):
		return pkt.qd.qname, pkt.qd.qtype, pkt.qd.qclass

	def get(self, pkt):
		if self.enabled:
			return self.cache.get(self.__generate_key(pkt), None)

	def set(self, pkt, response):
		if self.enabled:
			self.cache[self.__generate_key(DNS(pkt))] = {'response': response, 'time': time.time()}


class DNSProxyHandler(BaseRequestHandler):
	def send_packet(self, sock, pkt, response, cache=True):
		sock.sendto(response, self.client_address)
		if cache:
			self.server.cache.set(pkt, response)

	def handle(self):
		data, sock = self.request
		src, port = self.client_address
		request, request_type = parse_packet(self.client_address, data)

		# Try Cache
		cached_response = self.server.cache.get(request)
		if cached_response:
			response = DNS(cached_response.get('response'))
			response.id = request.id
			self.send_packet(sock, request, response.__bytes__())
			logging.info('TX: {}:{} - CACHED, Question: {}'.format(src, port, request.qd.qname))
			return

		# Try Hooks
		response = process_packet(request, self.server.hooks, self.client_address, request_type)
		if response:
			self.send_packet(sock, request, response)
			return

		# Try DNS Server
		logging.info('TX: {}:{} - Forwarding DNS record(s) from {}'.format(src, port, self.server.dns_server))
		response = self.__forward_request_to_dns_server(data)
		self.send_packet(sock, request, response, cache=False)

	def __forward_request_to_dns_server(self, data):
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # socket for the remote DNS server
		sock.connect((self.server.dns_server, 53))
		sock.sendall(data)
		sock.settimeout(60)
		rspdata = sock.recv(65535)
		sock.close()
		return rspdata


class DNSProxyServer(ThreadingUDPServer):
	def __init__(self, dns_server, disable_cache=False, host='127.0.0.1', port=53, hooks=None):
		self.dns_server = dns_server
		self.cache = Cache()
		self.cache.enabled = not disable_cache
		self.hooks = hooks
		ThreadingUDPServer.__init__(self, (host, port), DNSProxyHandler)


def run(hooks):
	import optparse
	import sys
	parser = optparse.OptionParser()
	parser.add_option('-H', '--host', dest='host', default='127.0.0.1',
	                  help='specify the address to listen on (default 127.0.0.1)')
	parser.add_option('-p', '--port', dest='port', default=53, type='int',
	                  help='specify the port to listen on (default 53)')
	parser.add_option('-s', '--server', dest='dns_server', metavar='<server>',
	                  help='specify the delegating dns server (required)')
	parser.add_option('-C', '--no-cache', dest='disable_cache', default=False, action='store_true',
	                  help='disable dns cache (default false)')
	parser.add_option('-l', '--log-level', dest='log_level', default=20, type='int', metavar='<level>',
	                  help='set the log level (10: debug, 20: info/default, 30: warning)')

	opts, args = parser.parse_args()
	if not opts.dns_server:
		parser.print_help()
		sys.exit(1)

	logging.basicConfig(format='%(asctime)-15s  %(levelname)-10s  %(message)s', level=opts.log_level)
	logging.info('Host:        ' + opts.host)
	logging.info('Port:        ' + str(opts.port))
	logging.info('DNS Server:  ' + opts.dns_server)
	logging.info('Cache:       ' + ('disabled' if opts.disable_cache else 'enabled'))
	logging.info('Log level:   ' + logging.getLevelName(opts.log_level))

	hook_dict = {}
	for hook in hooks:
		if hook.record_type.name not in hook_dict:
			hook_dict[hook.record_type.name] = []
		hook_dict[hook.record_type.name].append(hook)

	dns_server = DNSProxyServer(opts.dns_server,
	                            disable_cache=opts.disable_cache,
	                            host=opts.host,
	                            port=opts.port,
	                            hooks=hook_dict)
	dns_server.serve_forever()
