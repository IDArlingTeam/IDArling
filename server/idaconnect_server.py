import os
import sys
import json
import logging

from twisted.internet import reactor, protocol
from twisted.python import log

from shared.models import Database, Revision
from shared.packets import (EventBase, Command,
                            GetDatabases, GetDatabasesReply,
                            GetRevisions, GetRevisionsReply,
                            NewDatabase, NewRevision)
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
    logging.basicConfig(
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(logPath)],
        format='%(asctime)s | %(name)20s | %(levelname)7s: %(message)s',
        datefmt='%m-%d-%Y %H:%M:%S',
        level=logging.DEBUG)

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

    # -------------------------------------------------------------------------
    # Twisted Events
    # -------------------------------------------------------------------------

    def connectionMade(self):
        super(ServerProtocol, self).connectionMade()
        self._factory.addClient(self)

    def connectionLost(self, reason):
        super(ServerProtocol, self).connectionLost(reason)
        self._factory.removeClient(self)

    # -------------------------------------------------------------------------
    # Internal Events
    # -------------------------------------------------------------------------

    def _recvPacket(self, packet):
        if Command.isCommand(packet):
            # Parse the command
            cmd = Command.new(packet)
            # Call the handler
            self._handlers[cmd.__class__](cmd)

        elif EventBase.isEvent(packet):
            # Parse the event
            event = EventBase(**packet)
            # Send the event to all clients
            self._factory.sendPacketToAll(event, self)

        else:
            return False
        return True

    # -------------------------------------------------------------------------
    # Command Handlers
    # -------------------------------------------------------------------------

    def _handleGetDatabases(self, packet):
        dbs = self._factory.getDatabases()
        # Filter by hash if requested
        if 'hash' in packet and packet['hash']:
            dbs = [db for db in dbs if db.getHash() == packet['hash']]
        self.sendPacket(GetDatabasesReply(dbs))

    def _handleGetRevisions(self, packet):
        revs = self._factory.getRevisions()
        # Filter by hash if requested
        if 'hash' in packet and packet['hash']:
            revs = [rev for rev in revs if rev.getHash() == packet['hash']]
        # Filter by uuid if requested
        if 'uuid' in packet and packet['uuid']:
            revs = [rev for rev in revs if rev.getUUID() == packet['uuid']]
        self.sendPacket(GetRevisionsReply(revs))

    def _handleNewDatabase(self, packet):
        # FIXME: Make sure no db exists
        self._factory.getDatabases().append(packet['db'])

    def _handleNewRevision(self, packet):
        # FIXME: Make sure the db exists
        # FIXME: Make sure no rev exists
        self._factory.getRevisions().append(packet['rev'])


# -----------------------------------------------------------------------------
# Server Factory
# -----------------------------------------------------------------------------


class ServerFactory(protocol.Factory, object):

    def __init__(self):
        super(ServerFactory, self).__init__()

        # Variables initialization
        self._clients = []

        # FIXME: Use SQL database for storage
        self._databases = []
        self._revisions = []

    def buildProtocol(self, addr):
        return ServerProtocol(self)

    # -------------------------------------------------------------------------
    # Getters/Setters
    # -------------------------------------------------------------------------

    def addClient(self, client):
        # Add a client to the list
        self._clients.append(client)

    def removeClient(self, client):
        # Remove a client from the list
        self._clients.remove(client)

    def getDatabases(self):
        return self._databases

    def getRevisions(self):
        return self._revisions

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
