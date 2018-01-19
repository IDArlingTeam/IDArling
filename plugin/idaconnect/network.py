import logging

import json

import qt5reactor  # noqa
qt5reactor.install()  # noqa

from twisted.internet import reactor, protocol, defer
from twisted.internet.protocol import ReconnectingClientFactory
from twisted.protocols import basic

from events.events import Event
from util.misc import byteify

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 31013

logger = logging.getLogger('IDAConnect.Network')


class ClientProtocol(basic.LineReceiver, object):

    def __init__(self, factory):
        super(ClientProtocol, self).__init__()
        self._factory = factory
        self._connected = False
        self._incoming = defer.DeferredQueue()
        self._outgoing = defer.DeferredQueue()

    def connectionMade(self):
        logger.debug("Connected to server")
        self._connected = True
        d = self._outgoing.get()
        d.addCallback(self.sendLine)
        d.addErrback(logger.exception)
        d = self._incoming.get()
        d.addCallback(self.recv_packet)
        d.addErrback(logger.exception)

    def connectionLost(self, reason):
        logger.debug("Disconnected from server: %s" % reason)
        self._connected = False

    def send_packet(self, pkt):
        self._outgoing.put(pkt)

    def recv_packet(self, pkt):
        Event.new(byteify(json.loads(pkt)))()
        if self._connected:
            d = self._incoming.get()
            d.addCallback(self.recv_packet)
            d.addErrback(logger.exception)

    def sendLine(self, pkt):
        logger.debug("Sent packet: %s" % pkt)
        super(ClientProtocol, self).sendLine(pkt)
        if self._connected:
            d = self._outgoing.get()
            d.addCallback(self.sendLine)
            d.addErrback(logger.exception)

    def lineReceived(self, pkt):
        logger.debug("Received packet: %s" % pkt)
        self._incoming.put(pkt)


class ClientFactory(ReconnectingClientFactory, object):

    def __init__(self, network):
        super(ClientFactory, self).__init__()
        self._network = network

    def buildProtocol(self, addr):
        self._protocol = ClientProtocol(self)
        return self._protocol


class Network(object):

    def __init__(self, plugin):
        self._plugin = plugin

    def install(self):
        self._factory = ClientFactory(self)

        logger.debug("Connecting to %s:%s" % (SERVER_HOST, SERVER_PORT))
        reactor.connectTCP(SERVER_HOST, SERVER_PORT, self._factory)
        reactor.runReturn()

    def uninstall(self):
        logger.debug("Disconnecting")
        reactor.stop()

    def send_event(self, event):
        pkt = json.dumps(event)
        self._factory._protocol.send_packet(pkt)
