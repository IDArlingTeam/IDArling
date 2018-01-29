import logging
import os
import sqlite3

from twisted.internet import reactor, protocol  # type: ignore
from twisted.python import log                  # type: ignore

from .shared.commands import (GetDatabases, GetDatabasesReply,
                              GetRevisions, GetRevisionsReply,
                              NewDatabase, NewRevision,
                              UploadFile, DownloadFile, DownloadFileReply)
from .shared.mapper import Mapper
from .shared.models import Database, Revision
from .shared.packets import Command, AbstractEvent
from .shared.protocol import Protocol


MYPY = False
if MYPY:
    from typing import (Any, Callable, Dict, List, MutableMapping,
                        Optional, Tuple, Type)
    from twisted.internet.interfaces import IAddress  # type: ignore
    from twisted.python.failure import Failure        # type: ignore
    from .shared.packets import Packet


def startLogging():
    # type: () -> logging.Logger
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


class ServerProtocol(Protocol):
    """
    The server implementation of the protocol.
    """

    def __init__(self, factory):
        # type: (ServerFactory) -> None
        """
        Initialize the server protocol.

        :param factory: the server factory
        """
        super(ServerProtocol, self).__init__(logger)
        self._factory = factory

        # Setup command handlers
        self._handlers = {
            GetDatabases: self._handleGetDatabases,
            GetRevisions: self._handleGetRevisions,
            NewDatabase: self._handleNewDatabase,
            NewRevision: self._handleNewRevision,
            UploadFile: self._handleUploadFile,
            DownloadFile: self._handleDownloadFile
        }  # type: Dict[Type[Command], Callable[[Command], None]]

    def connectionMade(self):
        # type: () -> None
        """
        Called when a connection has been established.
        """
        super(ServerProtocol, self).connectionMade()
        self._factory.addClient(self)

        # Add host and port as a prefix to our logger
        peer = self.transport.getPeer()
        prefix = '%s:%s' % (peer.host, peer.port)

        class CustomAdapter(logging.LoggerAdapter):
            def process(self, msg,  # type: unicode
                        kwargs      # type: MutableMapping[str, Any]
                        ):
                # type: (...) -> Tuple[str, MutableMapping[str, Any]]
                return '(%s) %s' % (prefix, msg), kwargs

        self._logger = CustomAdapter(self._logger, {})  # type: ignore
        self._logger.info("Connected")

    def connectionLost(self, reason=protocol.connectionDone):
        # type: (Failure) -> None
        """
        Called when an established connection has been lost.

        :param reason: the reason of the loss
        """
        super(ServerProtocol, self).connectionLost(reason)
        self._factory.removeClient(self)
        self._logger.info("Disconnected: %s" % reason)

    def recvPacket(self, packet):
        # type: (Packet) -> bool
        """
        Called when a packet has been received.

        :param packet: the packet
        :return: has the packed been handled
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
        filesDir = os.path.join(os.path.dirname(__file__), 'files')
        filesDir = os.path.abspath(filesDir)
        if not os.path.exists(filesDir):
            os.makedirs(filesDir)
        fileName = rev.uuid + ('.i64' if rev.bits else '.idb')
        filePath = os.path.join(filesDir, fileName)

        # Write the file received to disk
        with open(filePath, 'wb') as outputFile:
            outputFile.write(packet.content)
        logger.info("Saved file %s" % fileName)

    def _handleDownloadFile(self, packet):
        rev = Revision.one(uuid=packet.uuid)
        filesDir = os.path.join(os.path.dirname(__file__), 'files')
        filesDir = os.path.abspath(filesDir)
        fileName = rev.uuid + ('.i64' if rev.bits else '.idb')
        filePath = os.path.join(filesDir, fileName)

        # Read file from disk and sent it
        packet = DownloadFileReply()
        with open(filePath, 'rb') as file_:
            packet.content = file_.read()
        self.sendPacket(packet)


class ServerFactory(protocol.Factory, object):  # type: ignore
    """
    The server factory implementation.
    """

    def __init__(self):
        # type: () -> None
        """
        Initialize the server factory.
        """
        super(ServerFactory, self).__init__()
        self._clients = []  # type: List[ServerProtocol]

        # Initialize database and bind mapper
        self._db = sqlite3.connect(':memory:', isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._mapper = Mapper(self._db)

    def buildProtocol(self, addr):
        # type: (IAddress) -> ServerProtocol
        """
        Called then a new protocol instance is needed.

        :param addr: the address of the remote party
        :return: the protocol instance
        """
        return ServerProtocol(self)

    def addClient(self, client):
        # type: (ServerProtocol) -> None
        """
        Add a client to the list of connected clients.

        :param client: the client
        """
        self._clients.append(client)

    def removeClient(self, client):
        # type: (ServerProtocol) -> None
        """
        Remove a client to the list of connected clients.

        :param client: the client
        """
        self._clients.remove(client)

    def sendPacketToAll(self, packet, ignore=None):
        # type: (Packet, Optional[ServerProtocol]) -> None
        """
        Send a packet to all connected clients.

        :param packet: the packet
        :param ignore: a client to ignore
        """
        for client in self._clients:
            if client != ignore:
                client.sendPacket(packet)


def main():
    # type: () -> None
    """
    The server main function.
    """
    reactor.listenTCP(31013, ServerFactory())
    reactor.run()


if __name__ == '__main__':
    main()
