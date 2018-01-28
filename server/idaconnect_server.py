import logging
import os
import sqlite3

from twisted.internet import reactor, protocol
from twisted.internet.interfaces import IAddress
from twisted.python import log
from twisted.python.failure import Failure

from shared.commands import (GetDatabases, GetDatabasesReply,
                             GetRevisions, GetRevisionsReply,
                             NewDatabase, NewRevision,
                             UploadFile, DownloadFile, DownloadFileReply)
from shared.mapper import Mapper
from shared.models import Database, Revision
from shared.packets import Packet, Command, AbstractEvent
from shared.protocol import Protocol


def startLogging():
    """
    Set up the main logger to write both to a log file and to the console
    using a specific format, and bind Twisted to the Python logger.

    :return: the main logger
    :rtype: logger.Logger
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


class ServerProtocol(Protocol):
    """
    The server implementation of the protocol.
    """

    def __init__(self, factory):
        """
        Initialize the server protocol.

        :param ServerFactory factory: the server factory
        """
        super(ServerProtocol, self).__init__(logger)
        self._factory = factory

        # Setup command handlers
        self._handlers[GetDatabases] = self._handleGetDatabases
        self._handlers[GetRevisions] = self._handleGetRevisions
        self._handlers[NewDatabase] = self._handleNewDatabase
        self._handlers[NewRevision] = self._handleNewRevision
        self._handlers[UploadFile] = self._handleUploadFile
        self._handlers[DownloadFile] = self._handleDownloadFile

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

        :param Failure reason: the reason of the loss
        """
        super(ServerProtocol, self).connectionLost(reason)
        self._factory.removeClient(self)
        self._logger.info("Disconnected: %s" % reason)

    def recvPacket(self, packet):
        """
        Called when a packet has been received.

        :param Packet packet: the packet
        :return: has the packed been handled
        :rtype: bool
        """
        if isinstance(packet, Command):
            # Call the corresponding handler
            self._handlers[packet.__class__](packet)

        elif isinstance(packet, AbstractEvent):
            # Forward the event to all clients
            self._factory.sendPacketToAll(packet, self)

        else:
            return False
        return True

    def _handleGetDatabases(self, packet):
        dbs = Database.all(hash=packet.hash)
        self.sendPacket(GetDatabasesReply(dbs))

    def _handleGetRevisions(self, packet):
        revs = Revision.all(uuid=packet.uuid, hash=packet.hash)
        self.sendPacket(GetRevisionsReply(revs))

    @staticmethod
    def _handleNewDatabase(packet):
        packet.db.create()

    @staticmethod
    def _handleNewRevision(packet):
        packet.rev.create()

    @staticmethod
    def _handleUploadFile(packet):
        rev = Revision.one(uuid=packet.uuid)
        assert isinstance(rev, Revision)
        filesDir = os.path.join(os.path.dirname(__file__), 'files')
        filesDir = os.path.abspath(filesDir)
        if not os.path.exists(filesDir):
            os.makedirs(filesDir)
        fileName = rev.uuid + ('.i64' if rev.bits else '.idb')
        filePath = os.path.join(filesDir, fileName)

        # Write the file received to disk
        with open(filePath, 'wb') as file_:
            file_.write(packet.content)
        logger.info("Saved file %s" % fileName)

    def _handleDownloadFile(self, packet):
        rev = Revision.one(uuid=packet.uuid)
        assert isinstance(rev, Revision)
        filesDir = os.path.join(os.path.dirname(__file__), 'files')
        filesDir = os.path.abspath(filesDir)
        fileName = rev.uuid + ('.i64' if rev.bits else '.idb')
        filePath = os.path.join(filesDir, fileName)

        # Read file from disk and sent it
        packet = DownloadFileReply()
        with open(filePath, 'rb') as file_:
            packet.content = file_.read()
        self.sendPacket(packet)


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

        # Initialize database and bind mapper
        self._db = sqlite3.connect(':memory:', isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._mapper = Mapper(self._db)

    def buildProtocol(self, addr):
        """
        Called then a new protocol instance is needed.

        :param IAddress addr: the address of the remote party
        :return: the protocol instance
        :rtype: ServerProtocol
        """
        return ServerProtocol(self)

    def addClient(self, client):
        """
        Add a client to the list of connected clients.

        :param ServerProtocol client: the client
        """
        self._clients.append(client)

    def removeClient(self, client):
        """
        Remove a client to the list of connected clients.

        :param ServerProtocol client: the client
        """
        self._clients.remove(client)

    def sendPacketToAll(self, packet, ignore=None):
        """
        Send a packet to all connected clients.

        :param Packet packet: the packet
        :param ServerProtocol ignore: a client to ignore
        """
        for client in self._clients:
            if client != ignore:
                client.sendPacket(packet)


# noinspection PyUnresolvedReferences
def main():
    """
    The server main function.
    """
    reactor.listenTCP(31013, ServerFactory())
    reactor.run()


if __name__ == '__main__':
    main()
