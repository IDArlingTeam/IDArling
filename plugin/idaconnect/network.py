import logging

import json

import qt5reactor  # noqa
qt5reactor.install()  # noqa

from twisted.internet import reactor, protocol, defer
from twisted.internet.protocol import ClientFactory
from twisted.protocols import basic

from events.events import Event
from util.misc import byteify


logger = logging.getLogger('IDAConnect.Network')


class ClientProtocol(basic.LineReceiver, object):

    def __init__(self, plugin):
        super(ClientProtocol, self).__init__()
        self._plugin = plugin
        self._connected = False
        self._incoming = defer.DeferredQueue()
        self._outgoing = defer.DeferredQueue()

    def isConnected(self):
        return self._connected

    def connectionMade(self):
        logger.debug("Connected to server")
        self._connected = True
        self._plugin.whenConnected()

        d = self._outgoing.get()
        d.addCallback(self.sendLine)
        d.addErrback(logger.exception)

        d = self._incoming.get()
        d.addCallback(self.recvPacket)
        d.addErrback(logger.exception)

    def connectionLost(self, reason):
        logger.debug("Disconnected from server: %s" % reason)
        self._connected = False
        self._plugin.whenDisconnected()

    def sendPacket(self, pkt):
        self._outgoing.put(pkt)

    def recvPacket(self, pkt):
        self._plugin.hooks.unhookAll()
        Event.new(byteify(json.loads(pkt)))()
        self._plugin.hooks.hookAll()
        if self._connected:
            d = self._incoming.get()
            d.addCallback(self.recvPacket)
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

    def isConnected(self):
        return self._protocol.isConnected()

    def sendPacket(self, pkt):
        if self.isConnected():
            self._protocol.sendPacket(pkt)


class Network(object):

    def __init__(self, plugin):
        super(Network, self).__init__()
        self._plugin = plugin
        self._installed = False

        self._host = ''
        self._port = 0

    def getHost(self):
        return self._host

    def getPort(self):
        return self._port

    def isConnected(self):
        return self._installed and self._factory.isConnected()

    def install(self):
        if self._installed:
            return
        self._factory = ClientFactory_(self._plugin)
        self._installed = True
        reactor.runReturn()

    def uninstall(self):
        if not self._installed:
            return
        self.disconnect()
        self._installed = False
        reactor.stop()

    def connect(self, host, port):
        if self._factory.isConnected():
            return
        self._host = host
        self._port = port
        logger.debug("Connecting to %s:%d" % (host, port))
        self._connector = reactor.connectTCP(host, port, self._factory)
        self._plugin.whenConnecting()

    def disconnect(self):
        if not self._factory.isConnected():
            return
        self._host = ''
        self._port = 0
        logger.debug("Disconnecting")
        self._connector.disconnect()
        self._plugin.whenDisconnected()

    def sendEvent(self, event):
        pkt = json.dumps(event)
        self._factory.sendPacket(pkt)
