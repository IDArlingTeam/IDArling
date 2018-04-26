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
import collections
import errno
import json
import socket
import ssl

from PyQt5.QtCore import QCoreApplication, QEvent, QObject, QSocketNotifier

from .packets import Packet, PacketDeferred, Query, Reply, Container


class PacketEvent(QEvent):
    """
    A Qt-event fired when a new packet is received by the client.
    """

    def __init__(self):
        """
        Initializes the new packet event.
        """
        evtype = QEvent.Type(QEvent.registerEventType())
        super(PacketEvent, self).__init__(evtype)


class ClientSocket(QObject):
    """
    A class wrapping a Python socket and integrated into the Qt event loop.
    """

    def __init__(self, logger, parent=None):
        """
        Initializes the client socket.

        :param logger: the logger to user
        """
        QObject.__init__(self, parent)
        self._logger = logger
        self._socket = None

        self._read_buffer = bytearray()
        self._read_notifier = None
        self._read_container = None

        self._write_buffer = bytearray()
        self._write_notifier = None
        self._write_container = None

        self._connected = False
        self._outgoing = collections.deque()
        self._incoming = collections.deque()

    @staticmethod
    def _chunkify(bs, n=65535):
        """
        Creates chunks of a specified size from a bytes string.

        :param bs: the bytes
        :param n: the size of a chunk
        :return: generator of chunks
        """
        for i in range(0, len(bs), n):
            yield bs[i:i + n]

    @property
    def connected(self):
        """
        Returns if the socket is connected.

        :return: is connected?
        """
        return self._connected

    def connect(self, sock):
        """
        Wraps the socket with the current object.

        :param sock: the socket
        """
        self._read_notifier = QSocketNotifier(sock.fileno(),
                                              QSocketNotifier.Read, self)
        self._read_notifier.activated.connect(self._notify_read)
        self._read_notifier.setEnabled(True)

        self._write_notifier = QSocketNotifier(sock.fileno(),
                                               QSocketNotifier.Write, self)
        self._write_notifier.activated.connect(self._notify_write)
        self._write_notifier.setEnabled(False)

        self._socket = sock
        self._connected = True

    def disconnect(self, err=None):
        """
        Terminates the current connection.

        :param err: the reason or None
        """
        if not self._socket:
            return
        if err:
            self._logger.warning("Connection lost")
            self._logger.exception(err)
        self._read_notifier.setEnabled(False)
        self._write_notifier.setEnabled(False)
        try:
            self._socket.close()
        except socket.error:
            pass
        self._socket = None
        self._connected = False

    def _notify_read(self):
        """
        Callback called when some data is ready to be read on the socket.
        """
        while True:
            try:
                data = self._socket.recv(4096)
            except socket.error as e:
                if e.errno not in (errno.EAGAIN, errno.EWOULDBLOCK) \
                        and not isinstance(e, ssl.SSLWantReadError) \
                        and not isinstance(e, ssl.SSLWantWriteError):
                    self.disconnect(e)
                break
            if not data:
                self.disconnect()
                break
            self._incoming.append(data)
        if self._incoming:
            QCoreApplication.instance().postEvent(self, PacketEvent())

    def _notify_write(self):
        """
        Callback called when some data is ready to written on the socket.
        """
        while True:
            if not self._write_buffer:
                if not self._outgoing:
                    break
                data = self._outgoing.popleft()
                self._write_buffer = bytearray(data)
            try:
                count = self._socket.send(self._write_buffer)
            except socket.error as e:
                if e.errno not in (errno.EAGAIN, errno.EWOULDBLOCK) \
                        and not isinstance(e, ssl.SSLWantReadError) \
                        and not isinstance(e, ssl.SSLWantWriteError):
                    self.disconnect(e)
                break
            if self._write_container is not None \
                    and self._write_container.upback:
                self._write_container.size += count  # trigger upload callback
                total = len(self._write_container.content)
                self._write_container.upback(self._write_container.size, total)
                if self._write_container.size >= total:
                    self._write_container = None
            self._write_buffer = self._write_buffer[count:]
        if not self._write_buffer:
            self._write_notifier.setEnabled(False)

    def event(self, event):
        """
        Callback called when a Qt event is fired.

        :param event: the event
        :return: was the event handled?
        """
        if isinstance(event, PacketEvent):
            self._dispatch()
            event.accept()
            return True
        else:
            event.ignore()
            return False

    def _dispatch(self):
        """
        Callback called when a packet event is fired.
        """
        while self._incoming:
            data = self._incoming.popleft()
            self._read_raw(data)

    def _read_raw(self, data):
        """
        Reads some raw from the underlying socket.

        :param data: the raw bytes
        """
        self._read_buffer.extend(data)

        while not self._read_container and b'\n' in self._read_buffer:
            lines = self._read_buffer.split(b'\n')
            self._read_buffer = bytearray(b'\n').join(lines[1:])
            self._read_line(lines[0])

        if self._read_container is not None:
            # Append raw data to content already received
            if self._read_container.downback:  # trigger download callback
                self._read_container.downback(len(self._read_buffer),
                                              self._read_container.size)
            if len(self._read_buffer) >= self._read_container.size:
                content = self._read_buffer[:self._read_container.size]
                self._read_buffer = self._read_buffer[len(content):]
                self._read_container.content = content
                self._handle_packet(self._read_container)
                self._read_container = None

    def _write_raw(self, data):
        """
        Writes some raw bytes to the underlying socket.

        :param data: the raw bytes
        """
        if not self._socket:
            return
        self._outgoing.append(data)
        if not self._write_notifier.isEnabled():
            self._write_notifier.setEnabled(True)

    def _read_line(self, line):
        """
        Reads a line from the underlying socket.

        :param line: the line
        """
        # Try to parse the line as a packet
        try:
            dct = json.loads(line.decode('utf-8'))
            packet = Packet.parse_packet(dct)
        except Exception as e:
            self._logger.warning("Invalid packet received: %s" % line)
            self._logger.exception(e)
            return

        # Wait for raw data if it is a container
        if isinstance(packet, Container):
            self._read_container = packet
            return  # do not go any further

        self._handle_packet(packet)

    def _write_line(self, line):
        """
        Writes a line to the underlying socket.

        :param line: the line
        """
        self._write_raw(line.encode('utf-8') + b'\n')

    def _handle_packet(self, packet):
        """
        Handle an incoming packet (used for replies).

        :param packet: the packet
        """
        self._logger.debug("Received packet: %s" % packet)

        # Notify for replies
        if isinstance(packet, Reply):
            packet.trigger_callback()

        # Otherwise forward to the subclass
        elif not self.recv_packet(packet):
            self._logger.warning("Unhandled packet received: %s" % packet)

    def send_packet(self, packet):
        """
        Sends a packet the other party.

        :param packet: the packet
        :return: a packet deferred if a reply is expected
        """
        if not self._connected:
            self._logger.warning("Sending packet while disconnected")
            return None

        # Try to build then sent the line
        try:
            line = json.dumps(packet.build_packet())
            if isinstance(packet, Container):
                packet.size -= len(line.encode('utf-8') + b'\n')
            self._write_line(line)
        except Exception as e:
            self._logger.warning("Invalid packet being sent: %s" % packet)
            self._logger.exception(e)

        self._logger.debug("Sending packet: %s" % packet)

        # Write raw data for containers
        if isinstance(packet, Container):
            self._write_container = packet
            for chunk in self._chunkify(packet.content):
                self._write_raw(chunk)

        # Queries return a packet deferred
        if isinstance(packet, Query):
            d = PacketDeferred()
            packet.register_callback(d)
            return d
        return None

    def recv_packet(self, packet):
        """
        Receives a packet from the other party.

        :param packet: the packet
        :return: has the packet been handled?
        """
        raise NotImplementedError("recv_packet() not implemented")


class ServerSocket(QObject):
    """
    A class wrapping a server socket and integrated into the Qt event loop.
    """

    def __init__(self, logger, parent=None):
        """
        Initialize the server socket.

        :param logger: the logger to use
        """
        QObject.__init__(self, parent)
        self._logger = logger
        self._socket = None
        self._connected = False
        self._accept_notifier = None

    @property
    def connected(self):
        """
        Returns if the socket is connected.

        :return: is connected?
        """
        return self._connected

    def connect(self, sock):
        """
        Wraps the socket with the current object.

        :param sock: the socket
        """
        self._accept_notifier = QSocketNotifier(sock.fileno(),
                                                QSocketNotifier.Read, self)
        self._accept_notifier.activated.connect(self._notify_accept)
        self._accept_notifier.setEnabled(True)

        self._socket = sock
        self._connected = True

    def disconnect(self, err=None):
        """
        Terminates the current connection.

        :param err: the reason or None
        """
        if not self._socket:
            return
        if err:
            self._logger.warning("Connection lost")
            self._logger.exception(err)
        self._accept_notifier.setEnabled(False)
        try:
            self._socket.close()
        except socket.error:
            pass
        self._socket = None
        self._connected = False

    def _notify_accept(self):
        """
        Callback called when a client is connecting.
        """
        while True:
            try:
                sock, address = self._socket.accept()
            except socket.error as e:
                if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    break
                self.disconnect(e)
                break
            self._accept(sock)

    def _accept(self, socket):
        """
        Handles the client who newly connected.

        :param socket: the socket
        """
        raise NotImplementedError('accept() is not implemented')
