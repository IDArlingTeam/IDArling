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
import platform
import socket
import time

from PyQt5.QtCore import QObject, QSocketNotifier, QTimer


DISCOVERY_REQUEST = "IDARLING_DISCOVERY_REQUEST"
DISCOVERY_REPLY = "IDARLING_DISCOVERY_REPLY"


class ClientsDiscovery(QObject):
    """
    This class is used by the server to discover client on the local network.
    It uses an UDP socket broadcasting the server hostname and port on the
    port 31013. A client will reply back with a simple message.
    """

    def __init__(self, logger, parent=None):
        super(ClientsDiscovery, self).__init__(parent)
        self._logger = logger
        self._info = None

        self._socket = None
        self._read_notifier = None
        self._started = False

        # Timer signaling that it's time to broadcast
        self._timer = QTimer()
        self._timer.setInterval(10000)
        self._timer.timeout.connect(self._send_request)

    def start(self, host, port, ssl):
        """Start the discovery process and broadcast the given information."""
        self._logger.debug("Starting clients discovery")
        self._info = "%s %d %s" % (host, port, ssl)
        # Create a datagram socket capable of broadcasting
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self._socket.settimeout(0)  # No timeout
        self._socket.setblocking(0)  # No blocking

        self._read_notifier = QSocketNotifier(
            self._socket.fileno(), QSocketNotifier.Read, self
        )
        self._read_notifier.activated.connect(self._notify_read)
        self._read_notifier.setEnabled(True)
        self._started = True
        self._timer.start()
        self._send_request()

    def stop(self):
        """Stop the discovery process."""
        self._logger.debug("Stopping clients discovery")
        self._read_notifier.setEnabled(False)
        try:
            self._socket.close()
        except socket.error:
            pass
        self._socket = None
        self._started = False
        self._timer.stop()

    def _send_request(self):
        """This function sends to discovery request packets."""
        self._logger.trace("Sending discovery request")
        request = DISCOVERY_REQUEST + " " + self._info
        request = request.encode("utf-8")
        while len(request):
            try:
                sent = self._socket.sendto(request, socket.MSG_DONTWAIT, ("<broadcast>", 31013))
                request = request[sent:]
            except socket.error as e:
                self._logger.warning("Couldn't send discovery request: {}".format(e))
                # Force return, otherwise the while loop will halt IDA
                # This is a temporary fix, and it's gonna yield the above
                # warning every every n seconds..
                return

    def _notify_read(self):
        """This function is called when a discovery reply is received."""
        response, address = self._socket.recvfrom(4096)
        response = response.decode("utf-8")
        if response == DISCOVERY_REPLY:
            self._logger.trace("Received discovery reply from %s:%d" % address)


class ServersDiscovery(QObject):
    """
    This class is used by the client to discover servers on the local network.
    It uses an UDP socket listening on port 31013 to received the request
    broadcasted by the server. Discovery server will be shown in the UI.
    """

    def __init__(self, logger, parent=None):
        super(ServersDiscovery, self).__init__(parent)
        self._logger = logger
        self._servers = []

        self._socket = None
        self._read_notifier = None
        self._started = False

    @property
    def servers(self):
        return self._servers

    def start(self):
        """Start the discovery process and listen for discovery requests."""
        self._logger.debug("Starting servers discovery")

        # Create a datagram socket bound on port 31013
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if platform.system() == "Darwin":
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self._socket.bind(("", 31013))
        self._socket.settimeout(0)
        self._socket.setblocking(0)

        self._read_notifier = QSocketNotifier(
            self._socket.fileno(), QSocketNotifier.Read, self
        )
        self._read_notifier.activated.connect(self._notify_read)
        self._read_notifier.setEnabled(True)
        self._started = True

    def stop(self):
        """Stop the discovery process."""
        self._logger.debug("Stopping servers discovery")
        self._read_notifier.setEnabled(False)
        try:
            self._socket.close()
        except socket.errno:
            pass
        self._socket = None
        self._started = False

    def _notify_read(self):
        """This function is called when a discovery request is received."""
        request, address = self._socket.recvfrom(4096)
        request = request.decode("utf-8")
        if request.startswith(DISCOVERY_REQUEST):
            self._logger.trace(
                "Received discovery request from %s:%d" % address
            )
            # Get the server information
            _, host, port, ssl = request.split()
            server = {"host": host, "port": int(port), "no_ssl": ssl != "True"}

            # Remove the old value
            self._servers = [(s, t) for (s, t) in self._servers if s != server]
            # Append the new value
            self._servers.append((server, time.time()))

            self._logger.trace("Sending discovery reply to %s:%d" % address)
            # Reply to the discovery request
            reply = DISCOVERY_REPLY
            reply = reply.encode("utf-8")
            try:
                self._socket.sendto(reply, address)
            except socket.error:
                self._logger.warning("Couldn't send discovery reply")
