import logging

import qt5reactor
qt5reactor.install()  # noqa

from twisted.internet import reactor

from ..module import Module
from client import ClientFactory


logger = logging.getLogger('IDAConnect.Network')


class Network(Module):
    """
    The network module, responsible for all interactions with the server.
    """

    def __init__(self, plugin):
        super(Network, self).__init__(plugin)

        self._host = ''
        self._port = 0
        self._factory = None
        self._connector = None

    @property
    def host(self):
        """
        Get the hostname of the server.

        :return: the host
        """
        return self._host

    @property
    def port(self):
        """
        Get the port of the server.

        :return: the port
        """
        return self._port

    @property
    def connected(self):
        """
        Return if we are connected to any server.

        :return: if connected
        """
        return self._installed and self._factory.isConnected()

    def _install(self):
        self._factory = ClientFactory(self._plugin)
        reactor.runReturn()
        return True

    def _uninstall(self):
        self.disconnect()
        reactor.stop()
        return True

    def connect(self, host, port):
        """
        Connect to the specified host and port.

        :param host: the host to connect to
        :param port: the port to connect to
        """
        # Make sure we're not already connected
        if self.connected:
            return

        # Do the actual connection process
        logger.info("Connecting to %s:%d..." % (host, port))
        self._host, self._port = host, port
        self._connector = reactor.connectTCP(host, port, self._factory)

        # Notify the plugin of the connection
        self._plugin.notifyConnecting()

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
        if self._connector:
            self._connector.disconnect()

    def sendPacket(self, packet):
        """
        Send a packet to the server.

        :param packet: the packet to send
        :return: a deferred of the reply
        """
        if self.connected:
            return self._factory.sendPacket(packet)
        return None
