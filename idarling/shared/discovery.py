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
import socket

from PyQt5.QtCore import QObject, QSocketNotifier, QTimer


DISCOVERY_REQUEST = "IDARLING_DISCOVERY_REQUEST"
DISCOVERY_REPLY = "IDARLING_DISCOVERY_REPLY"


class ClientsDiscovery(QObject):
    def __init__(self, logger, parent=None):
        super(ClientsDiscovery, self).__init__(parent)
        self._logger = logger
        self._info = None

        self._socket = None
        self._read_notifier = None
        self._started = False

        self._timer = QTimer()
        self._timer.setInterval(10000)
        self._timer.timeout.connect(self._send_request)

    @property
    def started(self):
        return self._started

    def start(self, host, port, ssl):
        self._logger.debug("Starting clients discovery...")
        self._info = "%s %d %s" % (host, port, ssl)

        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self._socket.settimeout(0)
        self._socket.setblocking(0)

        self._read_notifier = QSocketNotifier(
            self._socket.fileno(), QSocketNotifier.Read, self
        )
        self._read_notifier.activated.connect(self._notify_read)
        self._read_notifier.setEnabled(True)
        self._started = True
        self._timer.start()
        self._send_request()

    def stop(self):
        self._logger.debug("Stopping clients discovery...")
        self._read_notifier.setEnabled(False)
        try:
            self._socket.close()
        except socket.error:
            pass
        self._socket = None
        self._started = False
        self._timer.stop()

    def _send_request(self):
        self._logger.trace("Sending discovery request...")
        request = DISCOVERY_REQUEST + " " + self._info
        request = request.encode("utf-8")
        while len(request):
            try:
                sent = self._socket.sendto(request, ("<broadcast>", 31013))
                request = request[sent:]
            except socket.error:
                self._logger.warning("Couldn't send discovery request")

    def _notify_read(self):
        response, address = self._socket.recvfrom(4096)
        response = response.decode("utf-8")
        if response == DISCOVERY_REPLY:
            self._logger.trace("Received discovery reply from %s:%d" % address)


class ServersDiscovery(QObject):
    def __init__(self, logger, parent=None):
        super(ServersDiscovery, self).__init__(parent)
        self._logger = logger
        self._servers = []
        self._new_servers = []

        self._socket = None
        self._read_notifier = None
        self._started = False

        self._timer = QTimer()
        self._timer.setInterval(10000)
        self._timer.timeout.connect(self._trim_replies)

    @property
    def servers(self):
        return self._servers

    @property
    def started(self):
        return self._started

    def start(self):
        self._logger.debug("Starting servers discovery....")
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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
        self._timer.start()

    def stop(self):
        self._logger.debug("Stopping servers discovery...")
        self._read_notifier.setEnabled(False)
        try:
            self._socket.close()
        except socket.errno:
            pass
        self._socket = None
        self._started = False
        self._timer.stop()

    def _notify_read(self):
        request, address = self._socket.recvfrom(4096)
        request = request.decode("utf-8")
        if request.startswith(DISCOVERY_REQUEST):
            self._logger.trace(
                "Received discovery request from %s:%d" % address
            )
            _, host, port, ssl = request.split()
            server = {"host": host, "port": int(port), "no_ssl": ssl != "True"}
            if server not in self._servers:
                self._servers.append(server)
            if server not in self._new_servers:
                self._new_servers.append(server)
            self._logger.trace("Server discovered: %s" % server)
            self._logger.trace("Sending discovery reply to %s:%d..." % address)
            reply = DISCOVERY_REPLY
            reply = reply.encode("utf-8")
            self._socket.sendto(reply, address)

    def _trim_replies(self):
        self._logger.trace(
            "Discovered %d servers: %s" % (len(self.servers), self.servers)
        )
        self._servers = self._new_servers
        self._new_servers = []
