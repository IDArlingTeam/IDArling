# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
import json

from twisted.internet.protocol import connectionDone
from twisted.protocols import basic

from packets import Packet, PacketDeferred, Query, Reply, Container


class Protocol(basic.LineReceiver, object):
    """
    The protocol implementation that is common to the client and the server.
    """

    @staticmethod
    def _makeChunks(bs, n=65535):
        """
        Create chunk of a specified size from a specified bytes.

        :param bs: the bytes
        :param n: the size of a chunk
        :return: generator of chunks
        """
        for i in range(0, len(bs), n):
            yield bs[i:i + n]

    def __init__(self, logger):
        """
        Initialize the protocol.

        :param logger: the logger to use
        """
        super(Protocol, self).__init__()
        self._logger = logger

        self._connected = False
        self._content = b''
        self._container = None

    def connectionMade(self):
        """
        Called when the connection has been established.
        """
        self._connected = True

    def connectionLost(self, reason=connectionDone):
        """
        Called when an established connection has been lost.

        :param reason: the reason of the loss
        """
        self._connected = False

    def lineReceived(self, line):
        """
        Called when a line has been received.

        :param line: the line
        """
        # Try to parse the line as a packet
        try:
            dct = json.loads(line, object_hook=self._byteify)
            packet = Packet.parsePacket(dct)
        except Exception as e:
            self._logger.warning("Invalid packet received: %s" % line)
            self._logger.exception(e)
            return

        # Wait for raw data if it is a container
        if isinstance(packet, Container):
            self._content = b''
            self._container = packet
            self.setRawMode()
            return  # do not go any further

        self.packetReceived(packet)

    def rawDataReceived(self, data):
        """
        Called when some raw data has been received.

        :param data: the raw data
        """
        # Append raw data to content already received
        self._content += data
        if self._container.downback:  # trigger download callback
            self._container.downback(len(self._content), len(self._container))
        if len(self._content) >= len(self._container):
            self.setLineMode()
            self._container.content = self._content
            self.packetReceived(self._container)

    def packetReceived(self, packet):
        """
        Called when a packet has been received.

        :param packet: the packet
        """
        self._logger.debug("Received packet: %s" % packet)

        # Notify for replies
        if isinstance(packet, Reply):
            packet.triggerCallback()

        # Otherwise forward to the subclass
        elif not self.recvPacket(packet):
            self._logger.warning("Unhandled packet received: %s" % packet)

    def isConnected(self):
        """
        Return if the protocol is currently connected.

        :return: if we are connected
        """
        return self._connected

    def sendPacket(self, packet):
        """
        Send a packet the other party.

        :param packet: the packet
        :return: a packet deferred if a reply is expected
        """
        if not self._connected:
            self._logger.warning("Sending packet while disconnected")
            return None

        # Try to build then sent the line
        try:
            line = json.dumps(packet.buildPacket())
            super(Protocol, self).sendLine(line.encode('utf-8'))
        except Exception as e:
            self._logger.warning("Invalid packet being sent: %s" % packet)
            self._logger.exception(str(e))

        self._logger.debug("Sending packet: %s" % packet)

        # Write raw data for containers
        if isinstance(packet, Container):
            data = packet.content
            count, total = 0, len(data)
            for chunk in self._makeChunks(data):
                self.transport.write(chunk)
                count += len(chunk)
                if packet.upback:  # trigger upload callback
                    packet.upback(count, total)

        # Queries return a packet deferred
        if isinstance(packet, Query):
            d = PacketDeferred()
            packet.registerCallback(d)
            return d
        return None

    def recvPacket(self, packet):
        """
        Protocol subclasses should implement this method.

        :param packet: the packet received
        :return: if the packet has been handled
        """
        raise NotImplementedError("recvPacket() not implemented")

    def _byteify(self, data):
        """
        Recursively transform an object into a bytes instance.

        :param data: the object to transform
        :return: the object transformed
        """
        if isinstance(data, unicode):
            return data.encode('utf-8')
        elif isinstance(data, list):
            return [self._byteify(item) for item in data]
        elif isinstance(data, dict):
            return {self._byteify(key): self._byteify(value)
                    for key, value in data.iteritems()}
        return data
