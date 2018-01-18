import logging

import json

import qt5reactor
qt5reactor.install()

from twisted.internet import reactor, protocol, defer
from twisted.internet.protocol import ReconnectingClientFactory
from twisted.protocols import basic

from events.events import Event

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 31013

logger = logging.getLogger("IDAConnect.Network")

class ClientProtocol(basic.LineReceiver, object):

    def __init__(self, factory):
        super(ClientProtocol, self).__init__()
        self._factory = factory
        self._connected = False
        self._incoming = defer.DeferredQueue()
        self._outgoing = defer.DeferredQueue()

    def connectionMade(self):
        logger.debug('connected to server')
        self._connected = True
        self._outgoing.get().addCallback(self.sendLine)
        self._incoming.get().addCallback(self.recv_packet)

    def connectionLost(self, reason):
        logger.debug('disconnected from server')
        logger.debug('reason: %s' % reason)
        self._connected = False

    def send_packet(self, pkt):
        self._outgoing.put(pkt)

    def recv_packet(self, pkt):
        self._factory.recv_packet(pkt)
        if self._connected:
            self._incoming.get().addCallback(self.recv_packet)

    def sendLine(self, pkt):
        super(ClientProtocol, self).sendLine(pkt)
        if self._connected:
            self._outgoing.get().addCallback(self.sendLine)
 
    def lineReceived(self, pkt):
        self._incoming.put(pkt)

class ClientFactory(ReconnectingClientFactory, object):

    def __init__(self, network):
        super(ClientFactory, self).__init__()
        self._network = network

    def buildProtocol(self, addr):
        self._protocol = ClientProtocol(self)
        return self._protocol

    def send_packet(self, pkt):
        self._protocol.send_packet(pkt)

    def recv_packet(self, pkt):
        self._network.recv_packet(pkt)

class Network(object):

    def __init__(self, plugin):
        self._plugin = plugin

    def install(self):
        self._factory = ClientFactory(self)
        logger.debug('connectTCP(%s, %s)' % (SERVER_HOST, SERVER_PORT))
        reactor.connectTCP(SERVER_HOST, SERVER_PORT, self._factory)

    def uninstall(self):
        pass

    def send_event(self, event):
        pkt = json.dumps(event.to_dict())
        self._factory.send_packet(pkt)

    def recv_packet(self, pkt):
        Event.from_dict(json.loads(pkt)).call()
