from models import Database, Revision
from packets import Command, SimpleCommand, Query, Reply, Container

# -----------------------------------------------------------------------------
# All Commands
# -----------------------------------------------------------------------------


class GetDatabases(SimpleCommand, Query):
    CMD_TYPE = 'get_dbs'

    def __init__(self, hash=None):
        super(GetDatabases, self).__init__()
        self.hash = hash


class GetDatabasesReply(Command, Reply):
    QUERY = GetDatabases
    CMD_TYPE = 'get_dbs_reply'

    def __init__(self, dbs):
        super(GetDatabasesReply, self).__init__()
        self.dbs = dbs

    def buildCommand(self, dct):
        dct['dbs'] = [db.build(dict()) for db in self.dbs]

    def parseCommand(self, dct):
        self.dbs = [Database.new(db) for db in dct['dbs']]


class GetRevisions(SimpleCommand, Query):
    CMD_TYPE = 'get_revs'

    def __init__(self, hash=None, uuid=None):
        super(GetRevisions, self).__init__()
        self.hash = hash
        self.uuid = uuid


class GetRevisionsReply(Command, Reply):
    QUERY = GetRevisions
    CMD_TYPE = 'get_revs_reply'

    def __init__(self, revs):
        super(GetRevisionsReply, self).__init__()
        self.revs = revs

    def buildCommand(self, dct):
        dct['revs'] = [rev.build(dict()) for rev in self.revs]

    def parseCommand(self, dct):
        self.revs = [Revision.new(rev) for rev in dct['revs']]


class NewDatabase(Command):
    CMD_TYPE = 'new_db'

    def __init__(self, db):
        super(NewDatabase, self).__init__()
        self.db = db

    def buildCommand(self, dct):
        self.db.build(dct['db'])

    def parseCommand(self, dct):
        self.db = Database.new(dct['db'])


class NewRevision(Command):
    CMD_TYPE = 'new_rev'

    def __init__(self, rev):
        super(NewRevision, self).__init__()
        self.rev = rev

    def buildCommand(self, dct):
        self.rev.build(dct['rev'])

    def parseCommand(self, dct):
        self.rev = Revision.new(dct['rev'])


class UploadFile(Container, SimpleCommand):
    CMD_TYPE = 'upload_file'

    def __init__(self, hash, uuid):
        super(UploadFile, self).__init__()
        self.hash = hash
        self.uuid = uuid


class DownloadFile(Query, SimpleCommand):
    CMD_TYPE = 'download_file'

    def __init__(self, hash, uuid):
        super(DownloadFile, self).__init__()
        self.hash = hash
        self.uuid = uuid


class DownloadFileReply(Container, Command, Reply):
    QUERY = DownloadFile
    CMD_TYPE = 'download_file_reply'
