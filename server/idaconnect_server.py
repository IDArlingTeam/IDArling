import collections
import logging
import os
import sqlite3

from twisted.internet import reactor, protocol
from twisted.python import log

from shared.commands import (GetRepositories, GetBranches,
                             NewRepository, NewBranch,
                             UploadDatabase, DownloadDatabase,
                             Subscribe, Unsubscribe)
from shared.mapper import Mapper
from shared.models import Repository, Branch
from shared.packets import Command, Event as IEvent, _EventFactory
from shared.protocol import Protocol


def startLogging():
    """
    Set up the main logger to write both to a log file and to the console
    using a specific format, and bind Twisted to the Python logger.

    :return: the main logger
    """
    LOGGER_NAME = 'IDAConnect.Server'

    # Bind Twisted to Python log
    observer = log.PythonLoggingObserver(loggerName=LOGGER_NAME)
    observer.start()

    global logger
    logger = logging.getLogger(LOGGER_NAME)

    # Get path to the log file
    logDir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'logs'))
    if not os.path.exists(logDir):
        os.makedirs(logDir)
    logPath = os.path.join(logDir, 'idaconnect.%s.log' % os.getpid())

    # Configure the logger
    logger.setLevel(logging.DEBUG)
    logFormat = '[%(asctime)s][%(levelname)s] %(message)s'
    formatter = logging.Formatter(fmt=logFormat, datefmt='%H:%M:%S')

    # Log to the console
    streamHandler = logging.StreamHandler()
    streamHandler.setFormatter(formatter)
    logger.addHandler(streamHandler)

    # Log to the log file
    fileHandler = logging.FileHandler(logPath)
    fileHandler.setFormatter(formatter)
    logger.addHandler(fileHandler)

    return logger


logger = startLogging()


class Event(IEvent):
    """
    A class to represent events as seen by the server. The server relays the
    events to the interested clients, it doesn't know to interpret them.
    """
    __event__ = 'all'

    def buildEvent(self, dct):
        dct.update(self.__dict__)

    def parseEvent(self, dct):
        self.__dict__.update(dct)


class ServerProtocol(Protocol):
    """
    The server implementation of the protocol.
    """

    def __init__(self, factory):
        """
        Initialize the server protocol.

        :param factory: the server factory
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

        elif isinstance(packet, Event):
            # Forward the event to all clients
            self._factory.broadcastEvent(packet, self)

        else:
            return False
        return True

    def _handleGetRepositories(self, query):
        d = Repository.all(hash=query.hash)

        def callback(repos):
            self.sendPacket(GetRepositories.Reply(query, repos))
        d.addCallback(callback)

    def _handleGetBranches(self, query):
        d = Branch.all(uuid=query.uuid, hash=query.hash)

        def callback(branches):
            self.sendPacket(GetBranches.Reply(query, branches))
        d.addCallback(callback)

    def _handleNewRepository(self, query):
        d = query.repo.create()

        def callback(_):
            self.sendPacket(NewRepository.Reply(query))
        d.addCallback(callback)

    def _handleNewBranch(self, query):
        d = query.branch.create()

        def callback(_):
            self.sendPacket(NewBranch.Reply(query))
        d.addCallback(callback)

    def _handleUploadDatabase(self, query):
        def onBranchQuery(branch):
            filesDir = os.path.join(os.path.dirname(__file__), 'files')
            filesDir = os.path.abspath(filesDir)
            if not os.path.exists(filesDir):
                os.makedirs(filesDir)
            fileName = branch.uuid + ('.i64' if branch.bits == 64 else '.idb')
            filePath = os.path.join(filesDir, fileName)

            # Write the file received to disk
            with open(filePath, 'wb') as outputFile:
                outputFile.write(query.content)
            logger.info("Saved file %s" % fileName)
            self.sendPacket(UploadDatabase.Reply(query))
        Branch.one(uuid=query.uuid).addCallback(onBranchQuery)

    def _handleDownloadDatabase(self, query):
        def onBranchQuery(branch):
            filesDir = os.path.join(os.path.dirname(__file__), 'files')
            filesDir = os.path.abspath(filesDir)
            fileName = branch.uuid + ('.i64' if branch.bits == 64 else '.idb')
            filePath = os.path.join(filesDir, fileName)

            # Read file from disk and sent it
            reply = DownloadDatabase.Reply(query)
            with open(filePath, 'rb') as inputFile:
                reply.content = inputFile.read()
            self.sendPacket(reply)
        Branch.one(uuid=query.uuid).addCallback(onBranchQuery)

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

    def __init__(self):
        """
        Initialize the server factory.
        """
        super(ServerFactory, self).__init__()
        self._clients = collections.defaultdict(list)

        # Register abstract event as a default
        # FIXME: Find a better way to do this
        _EventFactory._EVENTS = collections.defaultdict(Event)

        # Initialize database and bind mapper
        filesDir = os.path.join(os.path.dirname(__file__), 'files')
        filesDir = os.path.abspath(filesDir)
        if not os.path.exists(filesDir):
            os.makedirs(filesDir)
        databasePath = os.path.join(filesDir, 'database.db')

        def setRowFactory(db):
            db.row_factory = sqlite3.Row
        self._db = Mapper('sqlite3', databasePath, check_same_thread=False,
                          cp_openfun=setRowFactory)
        d = self._db.initialize()
        d.addCallback(lambda _: logger.info("Database initialized"))
        d.addErrback(logger.exception)

    def buildProtocol(self, addr):
        """
        Called then a new protocol instance is needed.

        :param addr: the address of the remote party
        :return: the protocol instance
        """
        return ServerProtocol(self)

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

    def broadcastEvent(self, packet, sender):
        """
        Send a packet to all connected clients.

        :param packet: the packet
        :param sender: the sender
        """
        for client in self._clients[(sender.repo, sender.branch)]:
            if client != sender:
                client.sendPacket(packet)


def main():
    """
    The server main function.
    """
    reactor.listenTCP(31013, ServerFactory())
    reactor.run()


if __name__ == '__main__':
    main()
