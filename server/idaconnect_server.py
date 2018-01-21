import os
import sys
import json
import logging

from twisted.internet import reactor, protocol
from twisted.python import log

from shared.models import Database, Revision
from shared.packets import Command, ListDatabases, ListDatabasesReply
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
    logDir = os.path.abspath(os.path.dirname(__file__))
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
        self._handlers[ListDatabases] = self._handleListDatabases

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

        elif packet['type'] == 'event':  # FIXME: Find a better way
            # Send the event to all clients
            self._factory.sendLineToAll(line, self)

        else:
            return False
        return True

    # -------------------------------------------------------------------------
    # Command Handlers
    # -------------------------------------------------------------------------

    def _handleListDatabases(self, packet):
        dbs = self._factory.getDatabases()
        reply = ListDatabasesReply(dbs)
        self.sendPacket(reply)

# -----------------------------------------------------------------------------
# Server Factory
# -----------------------------------------------------------------------------


class ServerFactory(protocol.Factory, object):

    def __init__(self):
        super(ServerFactory, self).__init__()

        # Variables initialization
        self._clients = []

        # FIXME: Don't hardcode databases
        self._databases = [
            Database('A', 'B', 'C', 'D', [
                Revision('A', 'B', 'C')])]

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
