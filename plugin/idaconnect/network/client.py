import json
import logging

# Twisted imports
from twisted.internet import defer, reactor
from twisted.internet.protocol import ClientFactory as Factory

from ..shared.packets import Command, Event
from ..shared.protocol import Protocol


logger = logging.getLogger('IDAConnect.Network')

# -----------------------------------------------------------------------------
# Client Protocol
# -----------------------------------------------------------------------------


class ClientProtocol(Protocol):

    def __init__(self, plugin):
        super(ClientProtocol, self).__init__(logger)
        self._plugin = plugin

    # -------------------------------------------------------------------------
    # Twisted Events
    # -------------------------------------------------------------------------

    def connectionMade(self):
        super(ClientProtocol, self).connectionMade()
        logger.info("Connected")

        # Notify the plugin
        self._plugin.notifyConnected()

    # -------------------------------------------------------------------------
    # Internal Events
    # -------------------------------------------------------------------------

    def recvPacket(self, packet):
        if isinstance(packet, Command):
            # Call the command handler
            self._handlers[packet.__class__](packet)

        elif isinstance(packet, Event):
            # Call the event asynchronously
            def callEvent(packet):
                self._plugin.getCore().unhookAll()
                packet()
                self._plugin.getCore().hookAll()

            reactor.callLater(0, callEvent, packet)
        else:
            return False
        return True

# -----------------------------------------------------------------------------
# Client Factory
# -----------------------------------------------------------------------------


class ClientFactory(Factory, object):

    def __init__(self, plugin):
        super(ClientFactory, self).__init__()
        self._plugin = plugin

        self._protocol = ClientProtocol(plugin)
        self.isConnected = self._protocol.isConnected
        self.sendPacket = self._protocol.sendPacket

    def buildProtocol(self, addr):
        return self._protocol

    # -------------------------------------------------------------------------
    # Twisted Events
    # -------------------------------------------------------------------------

    def startedConnecting(self, connector):
        super(ClientFactory, self).startedConnecting(connector)

        # Notify the plugin
        self._plugin.notifyConnecting()

    def clientConnectionFailed(self, connector, reason):
        super(ClientFactory, self).clientConnectionFailed(connector, reason)
        logger.info("Connection failed: %s" % reason)

        # Notify the plugin
        self._plugin.notifyDisconnected()

    def clientConnectionLost(self, connector, reason):
        super(ClientFactory, self).clientConnectionLost(connector, reason)
        logger.info("Connection lost: %s" % reason)

        # Notify the plugin
        self._plugin.notifyDisconnected()
