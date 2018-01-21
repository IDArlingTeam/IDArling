import json
import logging

# Twisted imports
from twisted.internet import defer
from twisted.internet.protocol import ClientFactory as ClientFactory_

from ..events.events_abc import Event
from ..shared.packets import Command
from ..shared.protocol import Protocol
from ..utilities.misc import byteify


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

    def _recvPacket(self, packet):
        if Command.isCommand(packet):
            # Parse the command
            cmd = Command.new(packet)
            # Call the handler
            self._handlers[cmd.__class__](cmd)

        elif Event.isEvent(packet):
            # Call the event
            self._plugin.getCore().unhookAll()
            Event.new(byteify(packet))()
            self._plugin.getCore().hookAll()

        else:
            return False
        return True

# -----------------------------------------------------------------------------
# Client Factory
# -----------------------------------------------------------------------------


class ClientFactory(ClientFactory_, object):

    def __init__(self, plugin):
        super(ClientFactory, self).__init__()

        # Variables initialization
        self._protocol = ClientProtocol(plugin)

    def buildProtocol(self, addr):
        return self._protocol

    # -------------------------------------------------------------------------
    # Getters/Setters
    # -------------------------------------------------------------------------

    def isConnected(self):
        # Pass on to the protocol
        return self._protocol.isConnected()

    def sendPacket(self, packet):
        # Pass on to the protocol
        if self.isConnected():
            return self._protocol.sendPacket(packet)
