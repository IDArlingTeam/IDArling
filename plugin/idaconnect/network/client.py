import json
import logging

# Twisted imports
from twisted.internet import reactor, protocol, defer
from twisted.internet.protocol import ClientFactory as ClientFactory_
from twisted.protocols import basic

from ..events.events_abc import Event
from ..utilities.misc import byteify


logger = logging.getLogger('IDAConnect.Network')

# -----------------------------------------------------------------------------
# Client Protocol
# -----------------------------------------------------------------------------


class ClientProtocol(basic.LineReceiver, object):

    def __init__(self, plugin):
        super(ClientProtocol, self).__init__()
        self._plugin = plugin

        # Variables initialization
        self._connected = False
        self._incoming = defer.DeferredQueue()
        self._outgoing = defer.DeferredQueue()

    # -------------------------------------------------------------------------
    # Twisted Events
    # -------------------------------------------------------------------------

    def connectionMade(self):
        logger.debug("Connected to server")
        self._connected = True

        # Notify the plugin
        self._plugin.notifyConnected()

        # Add callback to outgoing queue
        d = self._outgoing.get()
        d.addCallback(self.sendLine)
        d.addErrback(logger.exception)

        # Add callback to incoming queue
        d = self._incoming.get()
        d.addCallback(self.recvPacket)
        d.addErrback(logger.exception)

    def connectionLost(self, reason):
        logger.debug("Disconnected from server: %s" % reason)
        self._connected = False

        # Notify the plugin
        self._plugin.notifyDisconnected()

    # -------------------------------------------------------------------------
    # Twisted Methods
    # -------------------------------------------------------------------------

    def sendLine(self, pkt):
        # Pass on the parent class
        logger.debug("Sent packet: %s" % pkt)
        super(ClientProtocol, self).sendLine(pkt)

        # Re-add callback to the outgoing queue
        if self._connected:
            d = self._outgoing.get()
            d.addCallback(self.sendLine)
            d.addErrback(logger.exception)

    def lineReceived(self, pkt):
        # Put packet into incoming queue
        logger.debug("Received packet: %s" % pkt)
        self._incoming.put(pkt)

    # -------------------------------------------------------------------------
    # Getters/Setters
    # -------------------------------------------------------------------------

    def isConnected(self):
        return self._connected

    def sendPacket(self, pkt):
        # Put packet into outgoing queue
        self._outgoing.put(pkt)

    def recvPacket(self, pkt):
        # Trigger the event
        self._plugin.getCore().unhookAll()
        Event.new(byteify(json.loads(pkt)))()
        self._plugin.getCore().hookAll()

        # Re-add callback to the incoming queue
        if self._connected:
            d = self._incoming.get()
            d.addCallback(self.recvPacket)
            d.addErrback(logger.exception)

# -----------------------------------------------------------------------------
# Client Factory
# -----------------------------------------------------------------------------


class ClientFactory(ClientFactory_, object):

    def __init__(self, plugin):
        super(ClientFactory, self).__init__()

        # Variables initialization
        self._protocol = ClientProtocol(plugin)

    # -------------------------------------------------------------------------
    # Getters/Setters
    # -------------------------------------------------------------------------

    def buildProtocol(self, addr):
        return self._protocol

    def isConnected(self):
        # Pass on to the protocol
        return self._protocol.isConnected()

    def sendPacket(self, pkt):
        # Pass on to the protocol
        if self.isConnected():
            self._protocol.sendPacket(pkt)
