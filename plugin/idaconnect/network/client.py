# Copyright (C) 2018 Alexandre Adamski
# Copyright (C) 2018 Joffrey Guilbon
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program.  If not, see <http://www.gnu.org/licenses/>.
import logging

from twisted.internet import reactor, task
from twisted.internet.protocol import ClientFactory as Factory

from ..shared.packets import Command, Event
from ..shared.protocol import Protocol

logger = logging.getLogger('IDAConnect.Network')


class ClientProtocol(Protocol):
    """
    The client implementation of the protocol.
    """

    def __init__(self, plugin):
        """
        Initialize the client protocol.

        :param plugin: the plugin instance
        """
        super(ClientProtocol, self).__init__(logger)
        self._plugin = plugin

    def connectionMade(self):
        """
        Called when the connection has been established.
        """
        super(ClientProtocol, self).connectionMade()
        logger.info("Connected")

        # Notify the plugin
        self._plugin.notifyConnected()

    def recvPacket(self, packet):
        """
        Called when a packet has been received.

        :param packet: the packet received
        :return: has the packet been handled
        """
        if isinstance(packet, Command):
            # Call the corresponding command handler
            self._handlers[packet.__class__](packet)

        elif isinstance(packet, Event):
            # Call the event asynchronously
            def callEvent(event):
                self._plugin.core.unhookAll()
                event()
                self._plugin.core.timestamp = \
                    max(self.plugin.core.timestamp, event.timestamp) + 1
                self._plugin.core.hookAll()

            d = task.deferLater(reactor, 0.0, callEvent, packet)
            d.addErrback(self._logger.exception)
        else:
            return False
        return True

    def sendPacket(self, packet):
        if isinstance(packet, Event):
            self._plugin.core.timestamp += 1
            packet.timestamp = self._plugin.core.timestamp
        return super(ClientProtocol, self).sendPacket(packet)


class ClientFactory(Factory, object):
    """
    The client factory implementation.
    """

    def __init__(self, plugin):
        """
        Initialize the client factory.

        :param plugin: the plugin instance
        """
        super(ClientFactory, self).__init__()
        self._plugin = plugin

        # Instantiate a new protocol
        self._protocol = ClientProtocol(plugin)
        self.isConnected = self._protocol.isConnected
        self.sendPacket = self._protocol.sendPacket

    def buildProtocol(self, addr):
        """
        Called then a new protocol instance is needed.

        :param addr: the address of the remote party
        :return: the protocol instance
        """
        return self._protocol

    def startedConnecting(self, connector):
        """
        Called when we are starting to connect to the server.

        :param connector: the connector used
        """
        super(ClientFactory, self).startedConnecting(connector)

        # Notify the plugin
        self._plugin.notifyConnecting()

    def clientConnectionFailed(self, connector, reason):
        """
        Called when the connection we attempted failed.

        :param connector: the connector used
        :param reason: the reason of the failure
        """
        super(ClientFactory, self).clientConnectionFailed(connector, reason)
        logger.info("Connection failed: %s" % reason)

        # Notify the plugin
        self._plugin.notifyDisconnected()

    def clientConnectionLost(self, connector, reason):
        """
        Called when a previously established connection was lost.

        :param connector: the connector used
        :param reason: the reason of the loss
        """
        super(ClientFactory, self).clientConnectionLost(connector, reason)
        logger.info("Connection lost: %s" % reason)

        # Notify the plugin
        self._plugin.notifyDisconnected()
