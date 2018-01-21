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
        self._connected = False
        self._incoming = defer.DeferredQueue()
        self._outgoing = defer.DeferredQueue()
        self._handlers = {}

    # -------------------------------------------------------------------------
    # Twisted Events
    # -------------------------------------------------------------------------

    def connectionMade(self):
        self._logger.debug("Connected")
        self._connected = True

        # Add callback to outgoing queue
        d = self._outgoing.get()
        d.addCallback(self.sendLine)
        d.addErrback(self._logger.exception)

        # Add callback to incoming queue
        d = self._incoming.get()
        d.addCallback(self.recvPacket)
        d.addErrback(self._logger.exception)

    def connectionLost(self, reason):
        self._logger.debug("Disconnected: %s" % reason)
        self._connected = False

    # -------------------------------------------------------------------------
    # Twisted Methods
    # -------------------------------------------------------------------------

    def sendLine(self, line):
        # Pass on to the parent class
        self._logger.debug("Sending packet: %s" % line)
        super(Protocol, self).sendLine(line)

        # Re-add callback to the outgoing queue
        if self._connected:
            d = self._outgoing.get()
            d.addCallback(self.sendLine)
            d.addErrback(self._logger.exception)

    def lineReceived(self, line):
        # Put packet into incoming queue
        self._logger.debug("Received packet: %s" % line)
        self._incoming.put(line)

    # -------------------------------------------------------------------------
    # Getters/Setters
    # -------------------------------------------------------------------------

    def isConnected(self):
        return self._connected

    def sendPacket(self, packet):
        # Put packet into outgoing queue
        line = json.dumps(packet)
        self._outgoing.put(line)

        # Queries return deferred
        if isinstance(packet, Query):
            d = defer.Deferred()
            packet.registerCallback(d)
            return d

    def recvPacket(self, line):
        packet = json.loads(line)
        if not Packet.isPacket(packet):
            self._logger.warning("Unknown packet received: %s" % packet)

        # Notify for replies
        if Reply.isReply(packet):
            Command.new(packet).notify()
        elif not self._recvPacket(packet):
            self._logger.warning("Unhandled packet received: %s" % packet)

        # Re-add callback to the incoming queue
        if self._connected:
            d = self._incoming.get()
            d.addCallback(self.recvPacket)
            d.addErrback(self._logger.exception)

    def _recvPacket(self, packet):
        # Protocols must implement this method
        raise NotImplementedError("recvPacket method not implemented")
