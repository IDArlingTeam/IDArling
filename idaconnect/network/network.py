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
import logging
import socket

from ..module import Module
from .client import Client

logger = logging.getLogger('IDAConnect.Network')


class Network(Module):
    """
    The network module, responsible for all interactions with the server.
    """

    def __init__(self, plugin):
        super(Network, self).__init__(plugin)
        self._host = ''
        self._port = 0
        self._client = None

    @property
    def host(self):
        """
        Get the hostname of the server.

        :return: the host
        """
        return self._host if self._client else ''

    @property
    def port(self):
        """
        Get the port of the server.

        :return: the port
        """
        return self._port if self._client else 0

    @property
    def connected(self):
        """
        Return if we are connected to any server.

        :return: if connected
        """
        return self._client.connected if self._client else False

    def _install(self):
        return True

    def _uninstall(self):
        self.disconnect()
        return True

    def connect(self, host, port):
        """
        Connect to the specified host and port.

        :param host: the host
        :param port: the port
        """
        # Make sure we're not already connected
        if self.connected:
            return

        # Create a client
        self._host = host
        self._port = port
        self._client = Client(self._plugin)

        # Do the actual connection process
        logger.info("Connecting to %s:%d..." % (host, port))
        # Notify the plugin of the connection
        self._plugin.notify_connecting()

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        try:
            sock.connect((host, port))
        except socket.error as e:
            logger.warning("Connection failed")
            logger.exception(e)
            self._client = None

            # Notify the plugin
            self._plugin.notify_disconnected()
            return
        self._client.connect(sock)

        # We're connected now
        logger.info("Connected")
        # Notify the plugin
        self._plugin.notify_connected()

    def disconnect(self):
        """
        Disconnect from the current server.
        """
        # Make sure we're actually connected
        if not self.connected:
            return

        # Do the actual disconnection process
        logger.info("Disconnecting...")
        if self._client:
            self._client.disconnect()
        self._client = None

        # Notify the plugin of the disconnection
        self._plugin.notify_disconnected()

    def send_packet(self, packet):
        """
        Send a packet to the server.

        :param packet: the packet to send
        :return: a deferred of the reply
        """
        if self.connected:
            return self._client.send_packet(packet)
        return None
