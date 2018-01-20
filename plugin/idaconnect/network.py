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

    def is_connected(self):
        return self._connected

    def connectionMade(self):
        logger.debug("Connected to server")
        self._connected = True
        self._plugin.when_connected()

        d = self._outgoing.get()
        d.addCallback(self.sendLine)
        d.addErrback(logger.exception)

        d = self._incoming.get()
        d.addCallback(self.recv_packet)
        d.addErrback(logger.exception)

    def connectionLost(self, reason):
        logger.debug("Disconnected from server: %s" % reason)
        self._connected = False
        self._plugin.when_disconnected()

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

        self._host = ''
        self._port = 0

    def get_host(self):
        return self._host

    def get_port(self):
        return self._port

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
        if self._factory.is_connected():
            return
        self._host = host
        self._port = port
        logger.debug("Connecting to %s:%d" % (host, port))
        self._connector = reactor.connectTCP(host, port, self._factory)
        self._plugin.when_connecting()

    def disconnect(self):
        if not self._factory.is_connected():
            return
        logger.debug("Disconnecting")
        self._connector.disconnect()
        self._plugin.when_disconnected()

    def send_event(self, event):
        pkt = json.dumps(event)
        self._factory.send_packet(pkt)
