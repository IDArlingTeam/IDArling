import sys

from twisted.internet import reactor, protocol
from twisted.protocols import basic
from twisted.python import log

SERVER_PORT = 31013

class ServerProtocol(basic.LineReceiver, object):

    def __init__(self, factory):
        super(ServerProtocol, self).__init__()
        self.factory = factory

    def _print(self, msg):
        prefix = '[%s] ' % str(self.transport.getPeer())
        print prefix + msg

    def connectionMade(self):
        self._print('connectionMade()')
        self.factory.clients.add(self)

    def connectionLost(self, reason):
        self._print('connectionLost(%s)' % reason)
        self.factory.clients.remove(self)

    def lineReceived(self, line):
        self._print('lineReceived(%s)' % line)
        for client in self.factory.clients:
            if client != self:
                client.sendLine(line)

    def sendLine(self, line):
        self._print('sendLine(%s)' % line)
        return super(ServerProtocol, self).sendLine(line)

class ServerFactory(protocol.Factory, object):

    def __init__(self):
        super(ServerFactory, self).__init__()
        self.clients = set()

    def buildProtocol(self, addr):
        return ServerProtocol(self)

def main():
    log.startLogging(sys.stdout)
    reactor.listenTCP(SERVER_PORT, ServerFactory())
    reactor.run()

if __name__ == '__main__':
    main()