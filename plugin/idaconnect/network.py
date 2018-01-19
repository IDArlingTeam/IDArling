import logging

import json

import qt5reactor  # noqa
qt5reactor.install()  # noqa

from twisted.internet import reactor, protocol, defer
from twisted.internet.protocol import ClientFactory
from twisted.protocols import basic

from events.events import Event
from util.misc import byteify

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 31013

logger = logging.getLogger('IDAConnect.Network')


class ClientProtocol(basic.LineReceiver, object):

    def __init__(self, plugin):
        super(ClientProtocol, self).__init__()
        self._plugin = plugin
        self._connected = False
        self._incoming = defer.DeferredQueue()
        self._outgoing = defer.DeferredQueue()

    def is_connected(self):
        return self._connected

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
        self._plugin.hooks.unhook_all()
        Event.new(byteify(json.loads(pkt)))()
        self._plugin.hooks.hook_all()
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


class ClientFactory_(ClientFactory, object):

    def __init__(self, plugin):
        super(ClientFactory_, self).__init__()
        self._protocol = ClientProtocol(plugin)

    def buildProtocol(self, addr):
        return self._protocol

    def is_connected(self):
        return self._protocol.is_connected()

    def send_packet(self, pkt):
        if self.is_connected():
            self._protocol.send_packet(pkt)


class Network(object):

    def __init__(self, plugin):
        super(Network, self).__init__()
        self._plugin = plugin
        self._installed = False

    def install(self):
        if self._installed:
            return
        self._factory = ClientFactory_(self._plugin)
        self.connect()
        self._installed = True

    def uninstall(self):
        if not self._installed:
            return
        self.disconnect()
        reactor.threadpool.stop()
        self._installed = False

    def connect(self):
        if self._factory.is_connected():
            return
        logger.debug("Connecting to %s:%s" % (SERVER_HOST, SERVER_PORT))
        self._connector = reactor.connectTCP(SERVER_HOST, SERVER_PORT,
                                             self._factory)

    def disconnect(self):
        if not self._factory.is_connected():
            return
        logger.debug("Disconnecting")
        self._connector.disconnect()

    def send_event(self, event):
        pkt = json.dumps(event)
        self._factory.send_packet(pkt)
