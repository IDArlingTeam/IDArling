import json
import logging

# Twisted imports
from twisted.internet import defer
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

        # Notify the plugin
        self._plugin.notifyConnected()

    def connectionLost(self, reason):
        super(ClientProtocol, self).connectionLost(reason)

        # Notify the plugin
        self._plugin.notifyDisconnected()

    # -------------------------------------------------------------------------
    # Internal Events
    # -------------------------------------------------------------------------

    def recvPacket(self, packet):
        if isinstance(packet, Command):
            # Call the command handler
            self._handlers[packet.__class__](packet)

        elif isinstance(packet, Event):
            # Call the event
            self._plugin.getCore().unhookAll()
            packet()
            self._plugin.getCore().hookAll()

        else:
            return False
        return True

# -----------------------------------------------------------------------------
# Client Factory
# -----------------------------------------------------------------------------


class ClientFactory(Factory, object):

    def __init__(self, plugin):
        super(ClientFactory, self).__init__()

        self._protocol = ClientProtocol(plugin)
        self.isConnected = self._protocol.isConnected
        self.sendPacket = self._protocol.sendPacket

    def buildProtocol(self, addr):
        return self._protocol
