from .models import Database, Revision
from .packets import (Command, DefaultCommand, ParentCommand,
                      Query as IQuery, Reply as IReply, Container)


class GetDatabases(ParentCommand):
    __command__ = 'get_dbs'

    class Query(IQuery, DefaultCommand):

        def __init__(self, hash=None):
            super(GetDatabases.Query, self).__init__()
            self.hash = hash

    class Reply(IReply, Command):

        def __init__(self, query, dbs):
            super(GetDatabases.Reply, self).__init__(query)
            self.dbs = dbs

        def buildCommand(self, dct):
            dct['dbs'] = [db.build(dict()) for db in self.dbs]

        def parseCommand(self, dct):
            self.dbs = [Database.new(db) for db in dct['dbs']]


class GetRevisions(ParentCommand):
    __command__ = 'get_revs'

    class Query(IQuery, DefaultCommand):

        def __init__(self, hash=None, uuid=None):
            super(GetRevisions.Query, self).__init__()
            self.hash = hash
            self.uuid = uuid

    class Reply(IReply, Command):

        def __init__(self, query, revs):
            super(GetRevisions.Reply, self).__init__(query)
            self.revs = revs

        def buildCommand(self, dct):
            dct['revs'] = [rev.build(dict()) for rev in self.revs]

        def parseCommand(self, dct):
            self.revs = [Revision.new(rev) for rev in dct['revs']]


class NewDatabase(ParentCommand):
    __command__ = 'new_db'

    class Query(IQuery, Command):

        def __init__(self, db):
            super(NewDatabase.Query, self).__init__()
            self.db = db

        def buildCommand(self, dct):
            self.db.build(dct['db'])

        def parseCommand(self, dct):
            self.db = Database.new(dct['db'])

    class Reply(IReply, Command):
        pass


class NewRevision(ParentCommand):
    __command__ = 'new_rev'

    class Query(IQuery, Command):

        def __init__(self, rev):
            super(NewRevision.Query, self).__init__()
            self.rev = rev

        def buildCommand(self, dct):
            self.rev.build(dct['rev'])

        def parseCommand(self, dct):
            self.rev = Revision.new(dct['rev'])

    class Reply(IReply, Command):
        pass


class UploadFile(ParentCommand):
    __command__ = 'upload_file'

    class Query(IQuery, Container, DefaultCommand):

        def __init__(self, hash, uuid):
            super(UploadFile.Query, self).__init__()
            self.hash = hash
            self.uuid = uuid

    class Reply(IReply, Command):
        pass


class DownloadFile(ParentCommand):
    __command__ = 'download_file'

    class Query(IQuery, DefaultCommand):

        def __init__(self, hash, uuid):
            super(DownloadFile.Query, self).__init__()
            self.hash = hash
            self.uuid = uuid

    class Reply(IReply, Container, Command):
        pass
