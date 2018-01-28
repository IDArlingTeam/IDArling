import logging

from twisted.internet import reactor, task
from twisted.internet.interfaces import IAddress, IConnector
from twisted.internet.protocol import ClientFactory as Factory
from twisted.python.failure import Failure

from ..shared.packets import Packet, Command, Event
from ..shared.protocol import Protocol

logger = logging.getLogger('IDAConnect.Network')


class ClientProtocol(Protocol):
    """
    The client implementation of the protocol.
    """

    def __init__(self, plugin):
        """
        Initialize the client protocol.

        :param IDAConnect plugin: the plugin instance
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

        :param Packet packet: the packet received
        :return: has the packet been handled
        :rtype: bool
        """
        if isinstance(packet, Command):
            # Call the corresponding command handler
            self._handlers[packet.__class__](packet)

        elif isinstance(packet, Event):
            # Call the event asynchronously
            def callEvent(event):
                self._plugin.core.unhookAll()
                event()
                self._plugin.core.hookAll()

            d = task.deferLater(reactor, 0.0, callEvent, packet)
            d.addErrback(self._logger.exception)
        else:
            return False
        return True


class ClientFactory(Factory, object):
    """
    The client factory implementation.
    """

    def __init__(self, plugin):
        """
        Initialize the client factory.

        :param IDAConnect plugin: the plugin instance
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

        :param IAddress addr: the address of the remote party
        :return: the protocol instance
        :rtype: ClientProtocol
        """
        return self._protocol

    def startedConnecting(self, connector):
        """
        Called when we are starting to connect to the server.

        :param IConnector connector: the connector used
        """
        super(ClientFactory, self).startedConnecting(connector)

        # Notify the plugin
        self._plugin.notifyConnecting()

    def clientConnectionFailed(self, connector, reason):
        """
        Called when the connection we attempted failed.

        :param IConnector connector: the connector used
        :param Failure reason: the reason of the failure
        """
        super(ClientFactory, self).clientConnectionFailed(connector, reason)
        logger.info("Connection failed: %s" % reason)

        # Notify the plugin
        self._plugin.notifyDisconnected()

    def clientConnectionLost(self, connector, reason):
        """
        Called when a previously established connection was lost.

        :param IConnector connector: the connector used
        :param Failure reason: the reason of the loss
        """
        super(ClientFactory, self).clientConnectionLost(connector, reason)
        logger.info("Connection lost: %s" % reason)

        # Notify the plugin
        self._plugin.notifyDisconnected()
