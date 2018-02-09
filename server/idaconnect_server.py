import collections
import logging
import os
import sqlite3

from twisted.internet import reactor, protocol
from twisted.python import log

from shared.commands import (GetDatabases, GetRevisions,
                             NewDatabase, NewRevision,
                             UploadFile, DownloadFile)
from shared.mapper import Mapper
from shared.models import Database, Revision
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

        # Setup command handlers
        self._handlers = {
            GetDatabases.Query: self._handleGetDatabases,
            GetRevisions.Query: self._handleGetRevisions,
            NewDatabase.Query: self._handleNewDatabase,
            NewRevision.Query: self._handleNewRevision,
            UploadFile.Query: self._handleUploadFile,
            DownloadFile.Query: self._handleDownloadFile
        }

    def connectionMade(self):
        """
        Called when a connection has been established.
        """
        super(ServerProtocol, self).connectionMade()
        self._factory.addClient(self)

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
        self._factory.removeClient(self)
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
            self._factory.sendPacketToAll(packet, self)

        else:
            return False
        return True

    def _handleGetDatabases(self, query):
        d = Database.all(hash=query.hash)

        def callback(dbs):
            self.sendPacket(GetDatabases.Reply(query, dbs))
        d.addCallback(callback)

    def _handleGetRevisions(self, query):
        d = Revision.all(uuid=query.uuid, hash=query.hash)

        def callback(revs):
            self.sendPacket(GetRevisions.Reply(query, revs))
        d.addCallback(callback)

    def _handleNewDatabase(self, query):
        d = query.db.create()

        def callback(_):
            self.sendPacket(NewDatabase.Reply(query))
        d.addCallback(callback)

    def _handleNewRevision(self, query):
        d = query.rev.create()

        def callback(_):
            self.sendPacket(NewRevision.Reply(query))
        d.addCallback(callback)

    def _handleUploadFile(self, query):
        def onRevision(rev):
            filesDir = os.path.join(os.path.dirname(__file__), 'files')
            filesDir = os.path.abspath(filesDir)
            if not os.path.exists(filesDir):
                os.makedirs(filesDir)
            fileName = rev.uuid + ('.i64' if rev.bits else '.idb')
            filePath = os.path.join(filesDir, fileName)

            # Write the file received to disk
            with open(filePath, 'wb') as outputFile:
                outputFile.write(query.content)
            logger.info("Saved file %s" % fileName)
            self.sendPacket(UploadFile.Reply(query))
        Revision.one(uuid=query.uuid).addCallback(onRevision)

    def _handleDownloadFile(self, query):
        def onRevision(rev):
            filesDir = os.path.join(os.path.dirname(__file__), 'files')
            filesDir = os.path.abspath(filesDir)
            fileName = rev.uuid + ('.i64' if rev.bits else '.idb')
            filePath = os.path.join(filesDir, fileName)

            # Read file from disk and sent it
            reply = DownloadFile.Reply(query)
            with open(filePath, 'rb') as inputFile:
                reply.content = inputFile.read()
            self.sendPacket(reply)
        Revision.one(uuid=query.uuid).addCallback(onRevision)


class ServerFactory(protocol.Factory, object):
    """
    The server factory implementation.
    """

    def __init__(self):
        """
        Initialize the server factory.
        """
        super(ServerFactory, self).__init__()
        self._clients = []

        # Register abstract event as a default
        # FIXME: Find a better way to do this
        _EventFactory._EVENTS = collections.defaultdict(Event)

        # Initialize database and bind mapper
        databaseDir = os.path.join(os.path.dirname(__file__), 'files')
        databaseDir = os.path.abspath(databaseDir)
        databasePath = os.path.join(databaseDir, 'database.db')

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

    def addClient(self, client):
        """
        Add a client to the list of connected clients.

        :param client: the client
        """
        self._clients.append(client)

    def removeClient(self, client):
        """
        Remove a client to the list of connected clients.

        :param client: the client
        """
        self._clients.remove(client)

    def sendPacketToAll(self, packet, ignore=None):
        """
        Send a packet to all connected clients.

        :param packet: the packet
        :param ignore: a client to ignore
        """
        for client in self._clients:
            if client != ignore:
                client.sendPacket(packet)


def main():
    """
    The server main function.
    """
    reactor.listenTCP(31013, ServerFactory())
    reactor.run()


if __name__ == '__main__':
    main()
