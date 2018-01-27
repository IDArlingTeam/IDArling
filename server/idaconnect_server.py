import os
import logging
import sqlite3

from twisted.internet import reactor, protocol
from twisted.python import log

from shared.commands import (GetDatabases, GetDatabasesReply,
                             GetRevisions, GetRevisionsReply,
                             NewDatabase, NewRevision,
                             UploadFile, DownloadFile, DownloadFileReply)
from shared.mapper import Mapper
from shared.models import Database, Revision
from shared.packets import Command, AbstractEvent
from shared.protocol import Protocol

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------


def startLogging():
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

# -----------------------------------------------------------------------------
# Server Protocol
# -----------------------------------------------------------------------------


class ServerProtocol(Protocol):

    def __init__(self, factory):
        super(ServerProtocol, self).__init__(logger)
        self._factory = factory

        # Setup handlers
        self._handlers[GetDatabases] = self._handleGetDatabases
        self._handlers[GetRevisions] = self._handleGetRevisions
        self._handlers[NewDatabase] = self._handleNewDatabase
        self._handlers[NewRevision] = self._handleNewRevision
        self._handlers[UploadFile] = self._handleUploadFile
        self._handlers[DownloadFile] = self._handleDownloadFile

    # -------------------------------------------------------------------------
    # Twisted Events
    # -------------------------------------------------------------------------

    def connectionMade(self):
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

    def connectionLost(self, reason):
        super(ServerProtocol, self).connectionLost(reason)
        self._factory.removeClient(self)
        self._logger.info("Disconnected: %s" % reason)

    # -------------------------------------------------------------------------
    # Internal Events
    # -------------------------------------------------------------------------

    def recvPacket(self, packet):
        if isinstance(packet, Command):
            # Call the handler
            self._handlers[packet.__class__](packet)

        elif isinstance(packet, AbstractEvent):
            # Send the event to all clients
            self._factory.sendPacketToAll(packet, self)

        else:
            return False
        return True

    # -------------------------------------------------------------------------
    # Command Handlers
    # -------------------------------------------------------------------------

    def _handleGetDatabases(self, packet):
        dbs = Database.all(hash=packet.hash)
        self.sendPacket(GetDatabasesReply(dbs))

    def _handleGetRevisions(self, packet):
        revs = Revision.all(uuid=packet.uuid, hash=packet.hash)
        self.sendPacket(GetRevisionsReply(revs))

    def _handleNewDatabase(self, packet):
        packet.db.create()

    def _handleNewRevision(self, packet):
        packet.rev.create()

    def _handleUploadFile(self, packet):
        rev = Revision.one(uuid=packet.uuid)
        filesDir = os.path.join(os.path.dirname(__file__), 'files')
        filesDir = os.path.abspath(filesDir)
        if not os.path.exists(filesDir):
            os.makedirs(filesDir)
        fileName = rev.uuid + ('.i64' if rev.bits else '.idb')
        filePath = os.path.join(filesDir, fileName)

        # Write the file to disk
        with open(filePath, 'wb') as file:
            file.write(packet.getContent())
        logger.info("Saved file %s" % fileName)

    def _handleDownloadFile(self, packet):
        rev = Revision.one(uuid=packet.uuid)
        filesDir = os.path.join(os.path.dirname(__file__), 'files')
        filesDir = os.path.abspath(filesDir)
        fileName = rev.uuid + ('.i64' if rev.bits else '.idb')
        filePath = os.path.join(filesDir, fileName)

        # Read file from disk
        packet = DownloadFileReply()
        with open(filePath, 'rb') as file:
            packet.setContent(file.read())
        self.sendPacket(packet)

# -----------------------------------------------------------------------------
# Server Factory
# -----------------------------------------------------------------------------


class ServerFactory(protocol.Factory, object):

    def __init__(self):
        super(ServerFactory, self).__init__()
        self._clients = []

        # Initialize database and mapper
        self._db = sqlite3.connect(':memory:', isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._mapper = Mapper(self._db)

    def buildProtocol(self, addr):
        return ServerProtocol(self)

    # -------------------------------------------------------------------------
    # Clients
    # -------------------------------------------------------------------------

    def addClient(self, client):
        # Add a client to the list
        self._clients.append(client)

    def removeClient(self, client):
        # Remove a client from the list
        self._clients.remove(client)

    # -------------------------------------------------------------------------
    # Network
    # -------------------------------------------------------------------------

    def sendPacketToAll(self, packet, ignore=None):
        # Send line to all client but ignore
        for client in self._clients:
            if client != ignore:
                client.sendPacket(packet)

# -----------------------------------------------------------------------------
# Server Main
# -----------------------------------------------------------------------------


def main():
    # Start listening on port 31013
    reactor.listenTCP(31013, ServerFactory())
    reactor.run()


if __name__ == '__main__':
    main()
