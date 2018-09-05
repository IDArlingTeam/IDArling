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
import ssl

from .client import Client
from .server import IntegratedServer
from ..module import Module
from ..shared.discovery import ServersDiscovery


class Network(Module):
    """
    This is the interface module. It is responsible for interacting with the
    server over the network. It manages the three sockets used with the plugin
    (client, discovery client, integrated server).
    """

    def __init__(self, plugin):
        super(Network, self).__init__(plugin)
        self._client = None
        self._server = None
        self._integrated = None
        self._discovery = ServersDiscovery(plugin.logger)

    @property
    def client(self):
        """Get the client socket."""
        return self._client

    @property
    def server(self):
        """Get the server information."""
        return self._server

    @property
    def discovery(self):
        """Get the discovery socket."""
        return self._discovery

    @property
    def connected(self):
        """Are we connected to a server?"""
        return self._client.connected if self._client else False

    def _install(self):
        self._discovery.start()
        return True

    def _uninstall(self):
        self._discovery.stop()
        self.disconnect()
        return True

    def connect(self, server):
        """Connect to the specified server."""
        # Make sure we're not already connected
        if self.connected:
            return False

        self._server = server.copy()  # Copy just in case
        host = self._server["host"]
        if host == "0.0.0.0":  # Windows can't connect to 0.0.0.0
            host = "127.0.0.1"
        port = self._server["port"]
        no_ssl = self._server["port"]

        # Do the actual connection process
        self._client = Client(self._plugin)
        self._plugin.logger.info("Connecting to %s:%d..." % (host, port))
        # Update the user interface
        self._plugin.interface.update()

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        # Wrap the socket in a SSL tunnel
        if not no_ssl:
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)

        try:
            sock.connect((host, port))
        except socket.error as e:
            self._plugin.logger.warning("Connection failed")
            self._plugin.logger.exception(e)
            self._client = None
            self._server = None

            # Update the user interface
            self._plugin.interface.update()
            return False
        sock.settimeout(0)  # No timeout
        sock.setblocking(0)  # No blocking
        self._client.connect(sock)

        # Set TCP keep-alive options
        cnt = self._plugin.config["keep"]["cnt"]
        intvl = self._plugin.config["keep"]["intvl"]
        idle = self._plugin.config["keep"]["idle"]
        self._client.set_keep_alive(cnt, intvl, idle)

        self._plugin.logger.info("Connected")
        # Update the user interface
        self._plugin.interface.update()
        # Subscribe to the events
        self._plugin.core.subscribe()
        return True

    def disconnect(self):
        """Disconnect from the current server."""
        # Do the actual disconnection process
        self._plugin.logger.info("Disconnecting...")
        if self.connected:
            self._client.disconnect()
        self._client = None
        self._server = None
        return True

    def send_packet(self, packet):
        """Send a packet to the server."""
        if self.connected:
            return self._client.send_packet(packet)
        return None

    def start_server(self):
        """Start the integrated server."""
        if self._integrated:
            return False
        self.disconnect()

        self._plugin.logger.info("Starting integrated server...")
        server = IntegratedServer(self._plugin)
        if not server.start("0.0.0.0"):
            return False  # Couldn't start the server
        self._integrated = server
        integrated_arg = {
            "host": "0.0.0.0",
            "port": server.port,
            "no_ssl": True,
        }
        # Connect the client to the server
        return self.connect(integrated_arg)

    def stop_server(self):
        """Stop the integrated server."""
        if not self._integrated:
            return False
        self._plugin.logger.info("Stopping integrated server...")
        self._integrated.stop()
        self._integrated = None
        self.disconnect()
        return True

    def server_running(self):
        """Is the integrated server running?"""
        return bool(self._integrated)
