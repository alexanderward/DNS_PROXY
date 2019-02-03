from abc import ABCMeta, abstractmethod

import logging


class DNSResponse(object):
	def __init__(self, section, dns_type, name, data, ttl=86400):
		self.dns_type = dns_type
		self.data = data
		self.name = name
		self.ttl = ttl
		self.section = section

	def __str__(self):
		return "Section: {}, Type: {}, Question: {}, Data: {}".format(self.section, self.dns_type, self.name, self.data)


class BaseHook(object):
	__slots__ = ('__record_type__', )
	__metaclass__ = ABCMeta
	__record_type__ = None

	def __init__(self):
		if self.record_type is None:
			raise Exception("You must set the Hook's DNS Request type")

	@property
	def record_type(self):
		return self.__record_type__

	@record_type.setter
	def record_type(self, record_type):
		self.__record_type__ = record_type

	@abstractmethod
	def process(self, ip, port, question):
		pass

	def check(self, ip, port, question):
		responses = self.process(ip, port, question)
		if responses:
			self.log(ip, port, question, responses)
		return responses

	def log(self, src, port, name, responses):
		log_buffer = "\t\t\t\t     "
		logging.info("TX: {}:{} - Hook: {}, Question: {}\n{}Answers: {}".format(
			src, port, self.__class__.__name__, name, log_buffer,
			"\n{}         ".format(log_buffer).join([str(x) for x in responses])))
