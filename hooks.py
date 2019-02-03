from core.types import DNSTypes, DNSSections
from core.utils import BaseHook, DNSResponse


class SampleARecordHook(BaseHook):
	record_type = DNSTypes.A  # Only A records will trigger this hook

	def process(self, client_ip, client_port, question_name):
		return [
			DNSResponse(section=DNSSections.AN, dns_type=DNSTypes.A, name=question_name, data='123.123.123.4', ttl=500),
			DNSResponse(section=DNSSections.AN, dns_type=DNSTypes.A, name=question_name, data='123.123.123.5', ttl=500),
			DNSResponse(section=DNSSections.NS, dns_type=DNSTypes.CNAME, name='anthem.is.fun', data='shift.com', ttl=500),
			DNSResponse(section=DNSSections.AR, dns_type=DNSTypes.CNAME, name='random.com', data='aws.shift.com', ttl=500),
		]
