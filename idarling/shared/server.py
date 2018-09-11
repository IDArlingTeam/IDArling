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
import os
import socket
import ssl

from .commands import (
    CreateDatabase,
    CreateProject,
    DownloadFile,
    InviteToLocation,
    JoinSession,
    LeaveSession,
    ListDatabases,
    ListProjects,
    UpdateFile,
    UpdateLocation,
    UpdateUserColor,
    UpdateUserName,
)
from .discovery import ClientsDiscovery
from .packets import Command, Event
from .sockets import ClientSocket, ServerSocket
from .storage import Storage


class ServerClient(ClientSocket):
    """
    This class represents a client socket for the server. It implements all the
    handlers for the packet the client is susceptible to send.
    """

    def __init__(self, logger, parent=None):
        ClientSocket.__init__(self, logger, parent)
        self._project = None
        self._database = None
        self._name = None
        self._color = None
        self._ea = None
        self._handlers = {}

    @property
    def project(self):
        """Get the user project."""
        return self._project

    @property
    def database(self):
        """Get the user database."""
        return self._database

    @property
    def name(self):
        """Get the user name."""
        return self._name

    @property
    def color(self):
        """Get the user color."""
        return self._color

    @property
    def ea(self):
        """Get the user address."""
        return self._ea

    def connect(self, sock):
        ClientSocket.connect(self, sock)

        # Add host and port as a prefix to our logger
        prefix = "%s:%d" % sock.getpeername()

        class CustomAdapter(logging.LoggerAdapter):
            def process(self, msg, kwargs):
                return "(%s) %s" % (prefix, msg), kwargs

        self._logger = CustomAdapter(self._logger, {})
        self._logger.info("Connected")

        # Setup command handlers
        self._handlers = {
            ListProjects.Query: self._handle_get_projects,
            ListDatabases.Query: self._handle_get_databases,
            CreateProject.Query: self._handle_new_project,
            CreateDatabase.Query: self._handle_new_database,
            UpdateFile.Query: self._handle_upload_file,
            DownloadFile.Query: self._handle_download_file,
            JoinSession: self._handle_subscribe,
            LeaveSession: self._handle_unsubscribe,
            InviteToLocation: self._handle_invite_to,
            UpdateLocation: self._handle_update_cursors,
            UpdateUserName: self._handle_user_renamed,
            UpdateUserColor: self._handle_user_color_changed,
        }

    def disconnect(self, err=None, notify=True):
        # Notify our peers we disconnected
        self.parent().reject(self)
        if self._project and self._database and notify:
            self.parent().forward_peers(self, LeaveSession(self.name, False))
        ClientSocket.disconnect(self, err)
        self._logger.info("Disconnected")

    def recv_packet(self, packet):
        if isinstance(packet, Command):
            # Call the corresponding handler
            self._handlers[packet.__class__](packet)

        elif isinstance(packet, Event):
            if not self._project or not self._database:
                self._logger.warning(
                    "Received a packet from an unsubscribed client"
                )
                return True

            # Check for de-synchronization
            tick = self.parent().storage.last_tick(
                self._project, self._database
            )
            if tick >= packet.tick:
                self._logger.warning("De-synchronization detected!")
                packet.tick = tick + 1

            # Save the event into the database
            self.parent().storage.insert_event(self, packet)
            # Forward the event to our peers
            self.parent().forward_peers(self, packet)
        else:
            return False
        return True

    def _handle_get_projects(self, query):
        projects = self.parent().storage.select_projects()
        self.send_packet(ListProjects.Reply(query, projects))

    def _handle_get_databases(self, query):
        databases = self.parent().storage.select_databases(query.project)
        for database in databases:
            database_info = database.project, database.name
            file_name = "%s_%s.idb" % database_info
            file_path = self.parent().server_file(file_name)
            if os.path.isfile(file_path):
                database.tick = self.parent().storage.last_tick(*database_info)
            else:
                database.tick = -1
        self.send_packet(ListDatabases.Reply(query, databases))

    def _handle_new_project(self, query):
        self.parent().storage.insert_project(query.project)
        self.send_packet(CreateProject.Reply(query))

    def _handle_new_database(self, query):
        self.parent().storage.insert_database(query.database)
        self.send_packet(CreateDatabase.Reply(query))

    def _handle_upload_file(self, query):
        database = self.parent().storage.select_database(
            query.project, query.database
        )
        file_name = "%s_%s.idb" % (database.project, database.name)
        file_path = self.parent().server_file(file_name)

        # Write the file received to disk
        with open(file_path, "wb") as output_file:
            output_file.write(query.content)
        self._logger.info("Saved file %s" % file_name)
        self.send_packet(UpdateFile.Reply(query))

    def _handle_download_file(self, query):
        database = self.parent().storage.select_database(
            query.project, query.database
        )
        file_name = "%s_%s.idb" % (database.project, database.name)
        file_path = self.parent().server_file(file_name)

        # Read file from disk and sent it
        reply = DownloadFile.Reply(query)
        with open(file_path, "rb") as input_file:
            reply.content = input_file.read()
        self.send_packet(reply)

    def _handle_subscribe(self, packet):
        self._project = packet.project
        self._database = packet.database
        self._name = packet.name
        self._color = packet.color
        self._ea = packet.ea

        # Inform our peers that we are subscribing
        packet.silent = False
        self.parent().forward_peers(self, packet)

        # Inform ourselves about our peers existence
        for peer in self.parent().get_peers(self):
            self.send_packet(
                JoinSession(
                    packet.project,
                    packet.database,
                    packet.tick,
                    peer.name,
                    peer.color,
                    peer.ea,
                )
            )

        # Send all missed events
        events = self.parent().storage.select_events(
            self._project, self._database, packet.tick
        )
        self._logger.debug("Sending %d missed events" % len(events))
        for event in events:
            self.send_packet(event)

    def _handle_unsubscribe(self, packet):
        # Inform others people that we are unsubscribing
        packet.silent = False
        self.parent().forward_peers(self, packet)

        # Inform ourselves that our peers ceased to exist
        for peer in self.parent().get_peers(self):
            self.send_packet(LeaveSession(peer.name))

        self._project = None
        self._database = None
        self._name = None
        self._color = None

    def _handle_invite_to(self, packet):
        target = packet.name
        packet.name = self._name

        def matches(other):
            return other.name == target or target == "everyone"

        self.parent().forward_peers(self, packet, matches)

    def _handle_update_cursors(self, packet):
        self.parent().forward_peers(self, packet)

    def _handle_user_renamed(self, packet):
        # TODO:
        # Check if the new_name is already used
        self._name = packet.new_name
        self.parent().forward_peers(self, packet)

    def _handle_user_color_changed(self, packet):
        self.parent().forward_peers(self, packet)


class Server(ServerSocket):
    """
    This class represents a server socket for the server. It is used by both
    the integrated and dedicated server implementations. It doesn't do much.
    """

    def __init__(self, logger, ssl, parent=None):
        ServerSocket.__init__(self, logger, parent)
        self._ssl = ssl
        self._clients = []

        # Initialize the storage
        self._storage = Storage(self.server_file("database.db"))
        self._storage.initialize()

        self._discovery = ClientsDiscovery(logger)

    @property
    def storage(self):
        """Get the storage in use."""
        return self._storage

    @property
    def host(self):
        """Gets the host name of the server."""
        return self._socket.getsockname()[0]

    @property
    def port(self):
        """Get the port number of the server."""
        return self._socket.getsockname()[1]

    def start(self, host, port=0):
        """Starts the server on the specified host and port."""
        self._logger.info("Starting server on %s:%d" % (host, port))

        # Load the system certificate chain
        if self._ssl:
            cert, key = self._ssl
            self._ssl = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self._ssl.load_cert_chain(certfile=cert, keyfile=key)

        # Create, bind and set the socket options
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except socket.error as e:
            self._logger.warning("Could not start server")
            self._logger.exception(e)
            return False
        sock.settimeout(0)  # No timeout
        sock.setblocking(0)  # No blocking
        sock.listen(5)
        self.connect(sock)

        # Start discovering clients
        host, port = sock.getsockname()
        self._discovery.start(host, port, self._ssl)
        return True

    def stop(self):
        """Terminates all the connections and stops the server."""
        self._logger.info("Shutting down server")
        for client in list(self._clients):
            client.disconnect(notify=False)
        self.disconnect()
        self._discovery.stop()
        return True

    def _accept(self, sock):
        client = ServerClient(self._logger, self)

        # Wrap the socket in an SSL tunnel
        if self._ssl:
            sock = self._ssl.wrap_socket(sock, server_side=True)

        sock.settimeout(0)  # No timeout
        sock.setblocking(0)  # No blocking
        client.connect(sock)
        self._clients.append(client)

    def reject(self, client):
        """Called when a client is disconnected."""
        self._clients.remove(client)

    def get_peers(self, client, matches=None):
        """Get the other clients on the same database."""
        peers = []
        for peer in self._clients:
            if (
                peer.project != client.project
                or peer.database != client.database
            ):
                continue
            if peer == client or (matches and not matches(peer)):
                continue
            peers.append(peer)
        return peers

    def forward_peers(self, client, packet, matches=None):
        """Sends the packet to the other clients on the same database."""
        for peer in self.get_peers(client, matches):
            peer.send_packet(packet)

    def server_file(self, filename):
        """Get the absolute path of a local resource."""
        raise NotImplementedError("server_file() not implemented")
