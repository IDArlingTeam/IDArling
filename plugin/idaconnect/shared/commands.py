from .models import Database, Revision
from .packets import Command, DefaultCommand, Query, Reply, Container


class GetDatabases(DefaultCommand, Query):
    __command__ = 'get_dbs'

    def __init__(self, hash=None):
        super(GetDatabases, self).__init__()
        self.hash = hash


class GetDatabasesReply(Command, Reply):
    __command__ = 'get_dbs_reply'
    __query__ = GetDatabases

    def __init__(self, dbs):
        super(GetDatabasesReply, self).__init__()
        self.dbs = dbs

    def buildCommand(self, dct):
        dct['dbs'] = [db.build(dict()) for db in self.dbs]

    def parseCommand(self, dct):
        self.dbs = [Database.new(db) for db in dct['dbs']]


class GetRevisions(DefaultCommand, Query):
    __command__ = 'get_revs'

    def __init__(self, hash=None, uuid=None):
        super(GetRevisions, self).__init__()
        self.hash = hash
        self.uuid = uuid


class GetRevisionsReply(Command, Reply):
    __command__ = 'get_revs_reply'
    __query__ = GetRevisions

    def __init__(self, revs):
        super(GetRevisionsReply, self).__init__()
        self.revs = revs

    def buildCommand(self, dct):
        dct['revs'] = [rev.build(dict()) for rev in self.revs]

    def parseCommand(self, dct):
        self.revs = [Revision.new(rev) for rev in dct['revs']]


class NewDatabase(Command, Query):
    __command__ = 'new_db'

    def __init__(self, db):
        super(NewDatabase, self).__init__()
        self.db = db

    def buildCommand(self, dct):
        self.db.build(dct['db'])

    def parseCommand(self, dct):
        self.db = Database.new(dct['db'])


class NewDatabaseReply(Command, Reply):
    __command__ = 'new_db_reply'
    __query__ = NewDatabase


class NewRevision(Command, Query):
    __command__ = 'new_rev'

    def __init__(self, rev):
        super(NewRevision, self).__init__()
        self.rev = rev

    def buildCommand(self, dct):
        self.rev.build(dct['rev'])

    def parseCommand(self, dct):
        self.rev = Revision.new(dct['rev'])


class NewRevisionReply(Command, Reply):
    __command__ = 'new_rev_reply'
    __query__ = NewRevision


class UploadFile(Container, DefaultCommand):
    __command__ = 'upload_file'

    def __init__(self, hash, uuid):
        super(UploadFile, self).__init__()
        self.hash = hash
        self.uuid = uuid


class DownloadFile(DefaultCommand, Query):
    __command__ = 'download_file'

    def __init__(self, hash, uuid):
        super(DownloadFile, self).__init__()
        self.hash = hash
        self.uuid = uuid


class DownloadFileReply(Container, Command, Reply):
    __command__ = 'download_file_reply'
    __query__ = DownloadFile
