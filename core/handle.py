import logging
from scapy.layers.dns import DNS, DNSQR, DNSRR

from core.types import DNSTypes

dns_opcodes = {0: "QUERY", 1: "IQUERY", 2: "STATUS"}


def log_received(client, pkt, record_type, cached=False):
	src, port = client
	logging.info('RX: {}:{} - {} - {}: {}  '.format(src, port, dns_opcodes[pkt.opcode], record_type.name,
	                                                ",".join([x.qname for x in pkt[DNS].qd])))


def process_questions(pkt, hooks, client):
	src, port = client
	response = []
	for hook in hooks:
		response = hook.check(src, port, pkt[DNS].qd.qname)
		if response:
			break
	return response


def parse_packet(client, data):
	pkt = DNS(data)
	record_type = DNSTypes(pkt[DNSQR].qtype)
	log_received(client, pkt, record_type)
	return pkt, record_type


def process_packet(pkt, hooks, client, record_type):
	try:
		type_hooks = hooks[record_type.name]
	except KeyError:
		type_hooks = []
	custom_responses = process_questions(pkt, type_hooks, client)
	if custom_responses:
		response_map = dict()
		for response in custom_responses:
			if response.section.value not in response_map:
				response_map[response.section.value] = []
			response_map[response.section.value].append(response)
		return create_dns_response_record(pkt, response_map)


def create_dns_response_record(pkt, response_map):
	sections = {
		'an': {
			'layer': None,
			'count': 0,
		},
		'ar': {
			'layer': None,
			'count': 0,
		},
		'ns': {
			'layer': None,
			'count': 0,
		}
	}
	payload = {'id': pkt[DNS].id}
	for section, responses in response_map.iteritems():
		sections[section]['count'] = len(responses)
		for response in responses:
			response_record = DNSRR(rrname=response.name, type=response.dns_type.value, rdata=response.data,
			                        ttl=response.ttl)
			if sections[section]['layer'] is None:
				sections[section]['layer'] = response_record
			else:
				sections[section]['layer'].add_payload(response_record)
		if sections[section]['count']:
			payload.update({section: sections[section]['layer'], "{}count".format(section): sections[section]['count']})
	return DNS(**payload).__bytes__()
