# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------


class Database(dict):

    def __init__(self, db_hash, db_name, db_type, db_date, db_revs):
        super(Database, self).__init__()
        self['db_hash'] = db_hash
        self['db_name'] = db_name
        self['db_type'] = db_type
        self['db_date'] = db_date
        self['db_revs'] = db_revs

    def getHash(self):
        return self['db_hash']

    def getName(self):
        return self['db_name']

    def getType(self):
        return self['db_type']

    def getDate(self):
        return self['db_date']

    def getRevs(self):
        return self['db_revs']


class Revision(dict):

    def __init__(self, rev_name, rev_auth, rev_date):
        super(Revision, self).__init__()
        self['rev_name'] = rev_name
        self['rev_auth'] = rev_auth
        self['rev_date'] = rev_date

    def getName(self):
        return self['rev_name']

    def getAuth(self):
        return self['rev_auth']

    def getDate(self):
        return self['rev_date']
