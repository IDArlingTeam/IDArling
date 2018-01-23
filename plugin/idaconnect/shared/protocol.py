import json

# Twisted imports
from twisted.internet import defer
from twisted.protocols import basic

from packets import Packet, Command, Query, Reply, Container

# -----------------------------------------------------------------------------
# Protocol
# -----------------------------------------------------------------------------


class Protocol(basic.LineReceiver, object):

    def __init__(self, logger):
        super(Protocol, self).__init__()
        self._logger = logger

        self._handlers = {}
        self._connected = False

        self._content = b''
        self._container = None

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
        # Try to parse the packet
        try:
            dct = json.loads(line, object_hook=self._byteify)
            packet = Packet.parsePacket(dct)
        except Exception as e:
            self._logger.warning("Unknown packet received: %s" % line)
            self._logger.exception(e)
            return

        # Wait for raw data in containers
        if isinstance(packet, Container):
            self._content = b''
            self._container = packet
            self.setRawMode()
            return  # do not go any further

        self.packetReceived(packet)

    def rawDataReceived(self, data):
        # Append raw data to container
        self._content += data
        if len(self._content) >= self._container.size:
            self.setLineMode()
            self._container.setContent(self._content)
            self.packetReceived(self._container)

    def packetReceived(self, packet):
        self._logger.debug("Received packet: %s" % packet)

        # Notify for replies
        if isinstance(packet, Reply):
            packet.triggerCallback()

        # Otherwise, go the usual way
        elif not self.recvPacket(packet):
            self._logger.warning("Unhandled packet received: %s" % packet)

    # -------------------------------------------------------------------------
    # Network
    # -------------------------------------------------------------------------

    def isConnected(self):
        return self._connected

    def sendPacket(self, packet, chunkback=None):
        if not self._connected:
            self._logger.warning("Sending packet while disconnected")
            return
        self._logger.debug("Sending packet: %s" % packet)

        # Try to build the packet
        line = json.dumps(packet.buildPacket())
        super(Protocol, self).sendLine(line.encode('utf-8'))

        # Write raw data in containers
        if isinstance(packet, Container):
            data = packet.getContent()
            count, total = 0, len(data)
            for chunk in self._makeChunks(data):
                self.transport.write(chunk)
                count += len(chunk)
                if chunkback:  # call chunk sent callback
                    chunkback(count, total)

        # Queries return deferred
        if isinstance(packet, Query):
            d = defer.Deferred()
            packet.registerCallback(d)
            return d

    def recvPacket(self, packet):
        # Protocols must implement this method
        raise NotImplementedError("recvPacket() not implemented")

    # -------------------------------------------------------------------------
    # Utilities
    # -------------------------------------------------------------------------

    def _byteify(self, data):
        if isinstance(data, unicode):
            return data.encode('utf-8')
        elif isinstance(data, list):
            return [self._byteify(item) for item in data]
        elif isinstance(data, dict):
            return {self._byteify(key): self._byteify(value)
                    for key, value in data.iteritems()}
        return data

    def _makeChunks(self, lst, n=1024):
        for i in range(0, len(lst), n):
            yield lst[i:i + n]
