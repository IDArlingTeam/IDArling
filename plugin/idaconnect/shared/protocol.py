import json

# Twisted imports
from twisted.internet import defer
from twisted.protocols import basic

from packets import Packet, Command, Query, Reply

# -----------------------------------------------------------------------------
# Protocol
# -----------------------------------------------------------------------------


class Protocol(basic.LineReceiver, object):

    def __init__(self, logger):
        super(Protocol, self).__init__()
        self._logger = logger

        # Variables initialization
        self._handlers = {}
        self._connected = False

    # -------------------------------------------------------------------------
    # Twisted Events
    # -------------------------------------------------------------------------

    def connectionMade(self):
        self._logger.info("Connected")
        self._connected = True

    def connectionLost(self, reason):
        self._logger.info("Disconnected: %s" % reason)
        self._connected = False

    def lineReceived(self, line):
        self._logger.debug("Received packet: %s" % line)

        packet = json.loads(line)
        if not Packet.isPacket(packet):
            self._logger.warning("Unknown packet received: %s" % packet)

        # Notify for replies
        if Reply.isReply(packet):
            Command.new(packet).notify()
        elif not self.recvPacket(packet):
            self._logger.warning("Unhandled packet received: %s" % packet)

    # -------------------------------------------------------------------------
    # Getters/Setters
    # -------------------------------------------------------------------------

    def isConnected(self):
        return self._connected

    def sendPacket(self, packet):
        self._logger.debug("Sending packet: %s" % packet)

        line = json.dumps(packet)
        super(Protocol, self).sendLine(line)

        # Queries return deferred
        if isinstance(packet, Query):
            d = defer.Deferred()
            packet.registerCallback(d)
            return d

    def recvPacket(self, packet):
        # Protocols must implement this method
        raise NotImplementedError("recvPacket method not implemented")
