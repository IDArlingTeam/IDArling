import logging

# Install qt5reactor first
import qt5reactor  # noqa
qt5reactor.install()  # noqa

# Twisted imports
from twisted.internet import reactor

from ..module import Module
from client import ClientFactory


logger = logging.getLogger('IDAConnect.Network')

# -----------------------------------------------------------------------------
# Network Module
# -----------------------------------------------------------------------------


class Network(Module):

    def __init__(self, plugin):
        super(Network, self).__init__(plugin)

        self._host = ''
        self._port = 0
        self._factory = None

    # -------------------------------------------------------------------------
    # Initialization
    # -------------------------------------------------------------------------

    def _install(self):
        # Create a new factory and start
        self._factory = ClientFactory(self._plugin)
        reactor.runReturn()

    def connect(self, host, port):
        # Check if we're already connected
        if self._factory.isConnected():
            return

        # Do the actual connection process
        logger.info("Connecting to %s:%d..." % (host, port))
        self._host, self._port = host, port
        self._connector = reactor.connectTCP(host, port, self._factory)

        # Notify plugin
        self._plugin.notifyConnecting()

    # -------------------------------------------------------------------------
    # Termination
    # -------------------------------------------------------------------------

    def _uninstall(self):
        # Disconnect and stop
        self.disconnect()
        reactor.stop()
        return True

    def disconnect(self):
        # Check if we're already disconnected
        if not self._factory.isConnected():
            return

        # Do the actual disconnection process
        logger.info("Disconnecting...")
        self._host, self._port = '', 0
        self._connector.disconnect()

    # -------------------------------------------------------------------------
    # Getters/Setters
    # -------------------------------------------------------------------------

    def getHost(self):
        return self._host

    def getPort(self):
        return self._port

    # -------------------------------------------------------------------------
    # Network
    # -------------------------------------------------------------------------

    def isConnected(self):
        # Pass on to the factory
        return self._installed and self._factory.isConnected()

    def sendPacket(self, packet):
        # Pass on to the factory
        if self.isConnected():
            return self._factory.sendPacket(packet)
