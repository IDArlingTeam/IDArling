# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------


class Database(dict):

    def __init__(self, hash, file, type, date):
        super(Database, self).__init__()
        self['hash'] = hash
        self['file'] = file
        self['type'] = type
        self['date'] = date

    def getHash(self):
        return self['hash']

    def getFile(self):
        return self['file']

    def getType(self):
        return self['type']

    def getDate(self):
        return self['date']


class Revision(dict):

    def __init__(self, hash, uuid, date):
        super(Revision, self).__init__()
        self['hash'] = hash
        self['uuid'] = uuid
        self['date'] = date

    def getHash(self):
        return self['hash']

    def getUUID(self):
        return self['uuid']

    def getDate(self):
        return self['date']
