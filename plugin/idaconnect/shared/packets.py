from models import Database, Revision

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


class GetDatabases(Query):
    TYPE = 'get_dbs'

    def ___init__(self, hash=None):
        super(GetDatabases, self).__init__()
        self['hash'] = hash


class GetDatabasesReply(Reply):
    TYPE = 'get_dbs_reply'
    QUERY = GetDatabases

    def __init__(self, dbs):
        super(GetDatabasesReply, self).__init__()
        self['dbs'] = []
        for db in dbs:
            if isinstance(db, dict):
                db = Database(**db)
            self['dbs'].append(db)


class GetRevisions(Query):
    TYPE = 'get_revs'

    def __init__(self, hash=None, uuid=None):
        super(GetRevisions, self).__init__()
        self['hash'] = hash
        self['uuid'] = uuid


class GetRevisionsReply(Reply):
    TYPE = 'get_revs_reply'
    QUERY = GetRevisions

    def __init__(self, revs):
        super(GetRevisionsReply, self).__init__()
        self['revs'] = []
        for rev in revs:
            if isinstance(rev, dict):
                rev = Revision(**rev)
            self['revs'].append(rev)


class NewDatabase(Command):
    TYPE = 'new_db'

    def __init__(self, db):
        super(NewDatabase, self).__init__()
        self['db'] = Database(**db) if isinstance(db, dict) else db


class NewRevision(Command):
    TYPE = 'new_rev'

    def __init__(self, rev):
        super(NewRevision, self).__init__()
        self['rev'] = Revision(**rev) if isinstance(rev, dict) else rev
