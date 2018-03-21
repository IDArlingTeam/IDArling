# Copyright (C) 2018 Alexandre Adamski
# Copyright (C) 2018 Joffrey Guilbon
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program.  If not, see <http://www.gnu.org/licenses/>.
import collections
import logging

from twisted.internet import reactor, protocol

from db import Database
from utils import localFile
from shared.commands import (GetRepositories, GetBranches,
                             NewRepository, NewBranch,
                             UploadDatabase, DownloadDatabase,
                             Subscribe, Unsubscribe)
from shared.models import AbstractEvent
from shared.packets import Command, EventFactory
from shared.protocol import Protocol

from utils import startLogging


class ServerProtocol(Protocol):
    """
    The server implementation of the protocol.
    """

    def __init__(self, factory, logger):
        """
        Initialize the server protocol.

        :param factory: the server factory
        :param logger: the server logger
        """
        super(ServerProtocol, self).__init__(logger)
        self._factory = factory
        self._repo = None
        self._branch = None

        # Setup command handlers
        self._handlers = {
            GetRepositories.Query: self._handleGetRepositories,
            GetBranches.Query: self._handleGetBranches,
            NewRepository.Query: self._handleNewRepository,
            NewBranch.Query: self._handleNewBranch,
            UploadDatabase.Query: self._handleUploadDatabase,
            DownloadDatabase.Query: self._handleDownloadDatabase,
            Subscribe: self._handleSubscribe,
            Unsubscribe: self._handleUnsubscribe,
        }

    @property
    def repo(self):
        """
        Get the current repository hash.

        :return: the hash
        """
        return self._repo

    @property
    def branch(self):
        """
        Get the current branch UUID.

        :return: the UUID
        """
        return self._branch

    def connectionMade(self):
        """
        Called when a connection has been established.
        """
        super(ServerProtocol, self).connectionMade()

        # Add host and port as a prefix to our logger
        peer = self.transport.getPeer()
        prefix = '%s:%s' % (peer.host, peer.port)

        class CustomAdapter(logging.LoggerAdapter):
            def process(self, msg, kwargs):
                return '(%s) %s' % (prefix, msg), kwargs

        self._logger = CustomAdapter(self._logger, {})
        self._logger.info("Connected")

    def connectionLost(self, reason=protocol.connectionDone):
        """
        Called when an established connection has been lost.

        :param reason: the reason of the loss
        """
        super(ServerProtocol, self).connectionLost(reason)
        self._factory.unregisterClient(self)
        self._logger.info("Disconnected: %s" % reason)

    def recvPacket(self, packet):
        """
        Called when a packet has been received.

        :param packet: the packet
        :return: has the packed been handled
        """
        if isinstance(packet, Command):
            # Call the corresponding handler
            self._handlers[packet.__class__](packet)

        elif isinstance(packet, AbstractEvent):
            if not self._repo or not self._branch:
                self._logger.warning(
                    "Received a packet from an unsubscribed client")
                return True

            # Fill the current repo and branch
            packet.hash = self._repo
            packet.uuid = self._branch

            # Forward the event to the factory
            self._factory.broadcastEvent(packet, self)
        else:
            return False
        return True

    def _handleGetRepositories(self, query):
        d = self._factory.db.selectRepos(query.hash)

        def callback(repos):
            self.sendPacket(GetRepositories.Reply(query, repos))
        d.addCallback(callback).addErrback(self._logger.exception)

    def _handleGetBranches(self, query):
        d = self._factory.db.selectBranches(query.uuid, query.hash)

        def callback(branches):
            self.sendPacket(GetBranches.Reply(query, branches))
        d.addCallback(callback).addErrback(self._logger.exception)

    def _handleNewRepository(self, query):
        d = self._factory.db.insertRepo(query.repo)

        def callback(_):
            self.sendPacket(NewRepository.Reply(query))
        d.addCallback(callback).addErrback(self._logger.exception)

    def _handleNewBranch(self, query):
        d = self._factory.db.insertBranch(query.branch)

        def callback(_):
            self.sendPacket(NewBranch.Reply(query))
        d.addCallback(callback).addErrback(self._logger.exception)

    def _handleUploadDatabase(self, query):
        def onBranchQuery(branch):
            fileName = branch.uuid + ('.i64' if branch.bits == 64 else '.idb')
            filePath = localFile(fileName)

            # Write the file received to disk
            with open(filePath, 'wb') as outputFile:
                outputFile.write(query.content)
            self._logger.info("Saved file %s" % fileName)
            self.sendPacket(UploadDatabase.Reply(query))
        d = self._factory.db.selectBranch(query.uuid, query.hash)
        d.addCallback(onBranchQuery).addErrback(self._logger.exception)

    def _handleDownloadDatabase(self, query):
        def onBranchQuery(branch):
            fileName = branch.uuid + ('.i64' if branch.bits == 64 else '.idb')
            filePath = localFile(fileName)

            # Read file from disk and sent it
            reply = DownloadDatabase.Reply(query)
            with open(filePath, 'rb') as inputFile:
                reply.content = inputFile.read()
            self.sendPacket(reply)
        d = self._factory.db.selectBranch(query.uuid, query.hash)
        d.addCallback(onBranchQuery).addErrback(self._logger.exception)

    def _handleSubscribe(self, packet):
        self._repo = packet.hash
        self._branch = packet.uuid
        self._factory.registerClient(self)

    def _handleUnsubscribe(self, _):
        self._factory.unregisterClient(self)
        self._repo = None
        self._branch = None


class ServerFactory(protocol.Factory, object):
    """
    The server factory implementation.
    """

    def __init__(self, logger):
        """
        Initialize the server factory.
        """
        super(ServerFactory, self).__init__()
        self._logger = logger
        self._clients = collections.defaultdict(list)

        # Initialize the database
        self._db = Database()
        d = self._db.initialize()
        d.addErrback(logger.exception)

        # Register abstract event as a default
        EventFactory._EVENTS = collections.defaultdict(lambda: AbstractEvent)

    def buildProtocol(self, addr):
        """
        Called then a new protocol instance is needed.

        :param addr: the address of the remote party
        :return: the protocol instance
        """
        return ServerProtocol(self, self._logger)

    def registerClient(self, client):
        """
        Add a client to the list of connected clients.

        :param client: the client
        """
        clients = self._clients[(client.repo, client.branch)]
        if client not in clients:
            clients.append(client)

    def unregisterClient(self, client):
        """
        Remove a client to the list of connected clients.

        :param client: the client
        """
        clients = self._clients[(client.repo, client.branch)]
        if client in clients:
            clients.remove(client)

    def broadcastEvent(self, event, sender):
        """
        Send a packet to all connected clients.

        :param event: the event
        :param sender: the sender
        """
        self._db.insertEvent(event)
        for client in self._clients[(sender.repo, sender.branch)]:
            if client != sender:
                client.sendPacket(event)

    @property
    def db(self):
        """
        Get the server's database.

        :return: the database
        """
        return self._db


class Server(object):
    """
    The IDAConnect server.
    """

    def __init__(self):
        """
        Instantiate the server and start listening.
        """
        logger = startLogging()
        factory = ServerFactory(logger)
        reactor.listenTCP(31013, factory)
        reactor.run()
