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
import os
import socket
import ssl
import sys

from PyQt5.QtCore import QCoreApplication, QEvent, QObject, QSocketNotifier

from .packets import Container, Packet, PacketDeferred, Query, Reply


class PacketEvent(QEvent):
    """
    This Qt event is fired when a new packet is received by the client,
    urging it to go check the incoming messages queue.
    """

    EVENT_TYPE = QEvent.Type(QEvent.registerEventType())

    def __init__(self):
        super(PacketEvent, self).__init__(PacketEvent.EVENT_TYPE)


class ClientSocket(QObject):
    """
    This class is acts a bridge between a client socket and the Qt event loop.
    By using a QSocketNotifier, we can be notified when some data is ready to
    be read or written on the socket, not requiring an extra thread.
    """

    MAX_DATA_SIZE = 65535

    def __init__(self, logger, parent=None):
        QObject.__init__(self, parent)
        self._logger = logger
        self._socket = None
        self._server = parent and isinstance(parent, ServerSocket)

        self._read_buffer = bytearray()
        self._read_notifier = None
        self._read_packet = None

        self._write_buffer = bytearray()
        self._write_notifier = None
        self._write_packet = None

        self._connected = False
        self._outgoing = collections.deque()
        self._incoming = collections.deque()

    @property
    def connected(self):
        """Is the underlying socket connected?"""
        return self._connected

    def wrap_socket(self, sock):
        """Sets the underlying socket to use."""
        self._read_notifier = QSocketNotifier(
            sock.fileno(), QSocketNotifier.Read, self
        )
        self._read_notifier.activated.connect(self._notify_read)
        self._read_notifier.setEnabled(True)

        self._write_notifier = QSocketNotifier(
            sock.fileno(), QSocketNotifier.Write, self
        )
        self._write_notifier.activated.connect(self._notify_write)
        self._write_notifier.setEnabled(True)

        self._socket = sock

    def disconnect(self, err=None):
        """Terminates the current connection."""
        if not self._socket:
            return

        self._logger.debug("Disconnected")
        if err:
            self._logger.exception(err)
        self._read_notifier.setEnabled(False)
        self._write_notifier.setEnabled(False)
        try:
            self._socket.shutdown(socket.SHUT_RDWR)
            self._socket.close()
        except socket.error:
            pass
        self._socket = None
        self._connected = False

    def set_keep_alive(self, cnt, intvl, idle):
        """
        Set the TCP keep-alive of the underlying socket.

        It activates after idle seconds of idleness, sends a keep-alive ping
        once every intvl seconds, and disconnects after `cnt`failed pings.
        """
        # Taken from https://github.com/markokr/skytools/
        tcp_keepcnt = getattr(socket, "TCP_KEEPCNT", None)
        tcp_keepintvl = getattr(socket, "TCP_KEEPINTVL", None)
        tcp_keepidle = getattr(socket, "TCP_KEEPIDLE", None)
        tcp_keepalive = getattr(socket, "TCP_KEEPALIVE", None)
        sio_keeplive_vals = getattr(socket, "SIO_KEEPALIVE_VALS", None)
        if (
            tcp_keepidle is None
            and tcp_keepalive is None
            and sys.platform == "darwin"
        ):
            tcp_keepalive = 0x10

        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if tcp_keepcnt is not None:
            self._socket.setsockopt(socket.IPPROTO_TCP, tcp_keepcnt, cnt)
        if tcp_keepintvl is not None:
            self._socket.setsockopt(socket.IPPROTO_TCP, tcp_keepintvl, intvl)
        if tcp_keepidle is not None:
            self._socket.setsockopt(socket.IPPROTO_TCP, tcp_keepidle, idle)
        elif tcp_keepalive is not None:
            self._socket.setsockopt(socket.IPPROTO_TCP, tcp_keepalive, idle)
        elif sio_keeplive_vals is not None:
            self._socket.ioctl(
                sio_keeplive_vals, (1, idle * 1000, intvl * 1000)
            )

    def _check_socket(self):
        """Check if the connection has been established yet."""
        # Ignore if you're already connected
        if self._connected:
            return True

        # Check if the connection was successful
        ret = self._socket.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if ret != 0 and ret != errno.EINPROGRESS and ret != errno.EWOULDBLOCK:
            self.disconnect(socket.error(ret, os.strerror(ret)))
            return False
        else:
            # Do SSL handshake if needed
            if isinstance(self._socket, ssl.SSLSocket):
                try:
                    self._socket.do_handshake()
                except socket.error as e:
                    if not isinstance(
                        e, ssl.SSLWantReadError
                    ) and not isinstance(e, ssl.SSLWantReadError):
                        self.disconnect(e)
                    return False

            self._connected = True
            self._logger.debug("Connected")
            return True

    def _notify_read(self):
        """Callback called when some data is ready to be read on the socket."""
        if not self._check_socket():
            return

        # Read as many bytes as possible
        try:
            data = self._socket.recv(ClientSocket.MAX_DATA_SIZE)
            if not data:
                self.disconnect()
                return
        except socket.error as e:
            if (
                e.errno not in (errno.EAGAIN, errno.EWOULDBLOCK)
                and not isinstance(e, ssl.SSLWantReadError)
                and not isinstance(e, ssl.SSLWantWriteError)
            ):
                self.disconnect(e)
            return  # No more data available
        self._read_buffer.extend(data)

        # Split the received data on new lines (= packets)
        while True:
            if self._read_packet is None:
                if b"\n" in self._read_buffer:
                    pos = self._read_buffer.index(b"\n")
                    line = self._read_buffer[:pos]
                    self._read_buffer = self._read_buffer[
                        pos + 1 :  # noqa: E203
                    ]

                    # Try to parse the line (= packet)
                    try:
                        dct = json.loads(line.decode("utf-8"))
                        self._read_packet = Packet.parse_packet(
                            dct, self._server
                        )
                    except Exception as e:
                        msg = "Invalid packet received: %s" % line
                        self._logger.warning(msg)
                        self._logger.exception(e)
                        continue
                else:
                    break  # Not enough data for a packet

            else:
                if isinstance(self._read_packet, Container):
                    avail = len(self._read_buffer)
                    total = self._read_packet.size

                    # Trigger the downback
                    if self._read_packet.downback:
                        self._read_packet.downback(min(avail, total), total)

                    # Read the container's content
                    if avail >= total:
                        self._read_packet.content = self._read_buffer[:total]
                        self._read_buffer = self._read_buffer[total:]
                    else:
                        break  # Not enough data for a packet

                self._incoming.append(self._read_packet)
                self._read_packet = None

        if self._incoming:
            QCoreApplication.instance().postEvent(self, PacketEvent())

    def _notify_write(self):
        """Callback called when some data is ready to written on the socket."""
        if not self._check_socket():
            return

        if not self._write_buffer:
            if not self._outgoing:
                return  # No more packets to send
            self._write_packet = self._outgoing.popleft()

            # Dump the packet as a line
            try:
                line = json.dumps(self._write_packet.build_packet())
                line = line.encode("utf-8") + b"\n"
            except Exception as e:
                msg = "Invalid packet being sent: %s" % self._write_packet
                self._logger.warning(msg)
                self._logger.exception(e)
                return

            # Write the container's content
            self._write_buffer.extend(bytearray(line))
            if isinstance(self._write_packet, Container):
                data = self._write_packet.content
                self._write_buffer.extend(bytearray(data))
                self._write_packet.size += len(line)

        # Send as many bytes as possible
        try:
            count = min(len(self._write_buffer), ClientSocket.MAX_DATA_SIZE)
            sent = self._socket.send(self._write_buffer[:count])
            self._write_buffer = self._write_buffer[sent:]
        except socket.error as e:
            if (
                e.errno not in (errno.EAGAIN, errno.EWOULDBLOCK)
                and not isinstance(e, ssl.SSLWantReadError)
                and not isinstance(e, ssl.SSLWantWriteError)
            ):
                self.disconnect(e)
            return  # Can't write anything

        # Trigger the upback
        if (
            isinstance(self._write_packet, Container)
            and self._write_packet.upback
        ):
            self._write_packet.size -= count
            total = len(self._write_packet.content)
            sent = max(total - self._write_packet.size, 0)
            self._write_packet.upback(sent, total)

        if not self._write_buffer and not self._outgoing:
            self._write_notifier.setEnabled(False)

    def event(self, event):
        """Callback called when a Qt event is fired."""
        if isinstance(event, PacketEvent):
            self._dispatch()
            event.accept()
            return True
        else:
            event.ignore()
            return False

    def _dispatch(self):
        """Callback called when a PacketEvent is received."""
        while self._incoming:
            packet = self._incoming.popleft()
            self._logger.debug("Received packet: %s" % packet)

            # Notify for replies
            if isinstance(packet, Reply):
                packet.trigger_callback()

            # Otherwise forward to the subclass
            elif not self.recv_packet(packet):
                self._logger.warning("Unhandled packet received: %s" % packet)

    def send_packet(self, packet):
        """Sends a packet the other party."""
        if not self._connected:
            self._logger.warning("Sending packet while disconnected")
            return None

        self._logger.debug("Sending packet: %s" % packet)

        # Enqueue the packet
        self._outgoing.append(packet)
        if not self._write_notifier.isEnabled():
            self._write_notifier.setEnabled(True)

        # Queries return a packet deferred
        if isinstance(packet, Query):
            d = PacketDeferred()
            packet.register_callback(d)
            return d
        return None

    def recv_packet(self, packet):
        """Receives a packet from the other party."""
        raise NotImplementedError("recv_packet() not implemented")


class ServerSocket(QObject):
    """
    This class is acts a bridge between a server socket and the Qt event loop.
    See the ClientSocket class for a more detailed explanation.
    """

    def __init__(self, logger, parent=None):
        QObject.__init__(self, parent)
        self._logger = logger
        self._socket = None
        self._connected = False
        self._accept_notifier = None

    @property
    def connected(self):
        """Is the underlying socket connected?"""
        return self._connected

    def connect(self, sock):
        """Sets the underlying socket to utilize."""
        self._accept_notifier = QSocketNotifier(
            sock.fileno(), QSocketNotifier.Read, self
        )
        self._accept_notifier.activated.connect(self._notify_accept)
        self._accept_notifier.setEnabled(True)

        self._socket = sock
        self._connected = True

    def disconnect(self, err=None):
        """Terminates the current connection."""
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
        """Callback called when a client is connecting."""
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
        """Handles the client who newly connected."""
        raise NotImplementedError("accept() is not implemented")
