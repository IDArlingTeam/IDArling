import logging

import qt5reactor  # noqa
qt5reactor.install()  # noqa

from twisted.internet import reactor

from ..module import Module
from ..shared.packets import Packet
from client import ClientFactory

logger = logging.getLogger('IDAConnect.Network')


class Network(Module):
    """
    The network module, responsible for all interactions with the server.
    """

    def __init__(self, plugin):
        """
        Instantiate the network module.
        :param IDAConnect plugin: the plugin instance
        """
        super(Network, self).__init__(plugin)

        self._host = ''
        self._port = 0
        self._factory = None
        self._connector = None

    def _install(self):
        """
        Install the network module: create its factory and start the reactor.

        :rtype: bool
        """
        self._factory = ClientFactory(self._plugin)
        # noinspection PyUnresolvedReferences
        reactor.runReturn()
        return True

    def connect(self, host, port):
        """
        Connect to the specified host and port.

        :param str host: the host to connect to
        :param int port: the port to connect to
        """
        # Make sure we're not already connected
        if self.connected:
            return

        # Do the actual connection process
        logger.info("Connecting to %s:%d..." % (host, port))
        self._host, self._port = host, port
        # noinspection PyUnresolvedReferences
        self._connector = reactor.connectTCP(host, port, self._factory)

        # Notify the plugin of the connection
        self._plugin.notifyConnecting()

    def _uninstall(self):
        """
        Uninstall the network module: disconnect and stop the reactor.

        :rtype: bool
        """
        self.disconnect()
        # noinspection PyUnresolvedReferences
        reactor.stop()
        return True

    def disconnect(self):
        """
        Disconnect from the current server.
        """
        # Make sure we're actually connected
        if not self.connected:
            return

        # Do the actual disconnection process
        logger.info("Disconnecting...")
        self._host, self._port = '', 0
        self._connector.disconnect()

    @property
    def host(self):
        """
        Get the hostname of the server.

        :rtype: str
        """
        return self._host

    @property
    def port(self):
        """
        Get the port of the server.

        :rtype: int
        """
        return self._port

    @property
    def connected(self):
        """
        Return if we are connected to any server.

        :rtype: bool
        """
        return self._installed and self._factory.isConnected()

    def sendPacket(self, packet):
        """
        Send a packet to the server.

        :param Packet packet: the packet to send
        :return PacketDeferred: a deferred of the reply
        """
        if self.connected:
            return self._factory.sendPacket(packet)
        return None
