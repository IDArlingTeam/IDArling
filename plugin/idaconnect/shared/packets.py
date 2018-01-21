from models import Database

# -----------------------------------------------------------------------------
# Packets
# -----------------------------------------------------------------------------


class Packet(dict):

    @staticmethod
    def isPacket(dct):
        return 'type' in dct

    def __init__(self, type):
        super(Packet, self).__init__()
        self['type'] = type

# -----------------------------------------------------------------------------
# Events
# -----------------------------------------------------------------------------


class EventBase(Packet):

    @staticmethod
    def isEvent(dct):
        return Packet.isPacket(dct) and dct['type'] == 'event'

    def __init__(self, **kwargs):
        super(EventBase, self).__init__('event')
        self.update(kwargs)

# -----------------------------------------------------------------------------
# Commands
# -----------------------------------------------------------------------------


class CommandMeta(type):
    _REGISTRY = {}

    @staticmethod
    def newCls(newType):
        return CommandMeta._REGISTRY[newType]

    def __new__(cls, name, bases, attrs):
        newCls = type.__new__(cls, name, bases, attrs)
        CommandMeta._REGISTRY[newCls.TYPE] = newCls
        return newCls


class Command(Packet):
    __metaclass__ = CommandMeta

    TYPE = None

    @staticmethod
    def new(dct):
        cmdCls = CommandMeta.newCls(dct['cmd_type'])
        del dct['type']
        del dct['cmd_type']
        return cmdCls(**dct)

    @staticmethod
    def isCommand(dct):
        return Packet.isPacket(dct) \
            and dct['type'] in ['cmd', 'cmd_query', 'cmd_reply']

    def __init__(self, type_='cmd'):
        super(Command, self).__init__(type_)
        self['cmd_type'] = self.TYPE

# -----------------------------------------------------------------------------
# Queries
# -----------------------------------------------------------------------------


class Query(Command):
    _CALLBACKS = []

    @staticmethod
    def isQuery(dct):
        return Command.isCommand(dct) and dct['type'] == 'cmd_query'

    @classmethod
    def registerCallback(cls, d):
        cls._CALLBACKS.append(d)

    @classmethod
    def triggerCallback(cls, reply):
        d = cls._CALLBACKS.pop()
        d.callback(reply)

    def __init__(self):
        super(Query, self).__init__('cmd_query')

# -----------------------------------------------------------------------------
# Replies
# -----------------------------------------------------------------------------


class Reply(Command):
    QUERY = None

    @staticmethod
    def isReply(dct):
        return Command.isCommand(dct) and dct['type'] == 'cmd_reply'

    def __init__(self):
        super(Reply, self).__init__('cmd_reply')

    def notify(self):
        self.QUERY.triggerCallback(self)

# -----------------------------------------------------------------------------
# All Packets
# -----------------------------------------------------------------------------


class ListDatabases(Query):
    TYPE = 'list_dbs'


class ListDatabasesReply(Reply):
    TYPE = 'list_dbs_reply'
    QUERY = ListDatabases

    def __init__(self, dbs):
        super(ListDatabasesReply, self).__init__()
        self['dbs'] = []
        for db in dbs:
            if not isinstance(db, Database):
                db = Database(**db)
            self['dbs'].append(db)
