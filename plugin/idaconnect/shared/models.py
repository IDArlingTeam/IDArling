from collections import defaultdict

# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------


class Model(object):

    @classmethod
    def new(cls, dct):
        obj = cls.__new__(cls)
        object.__init__(obj)
        obj.parse(dct)
        return obj

    def build(self, dct):
        raise NotImplementedError("build() not implemented")

    def parse(self, dct):
        raise NotImplementedError("parse() not implemented")

    def __repr__(self):
        items = ', '.join(['%s=%s' % (key, repr(value))
                           for key, value in self.__dict__.items()])
        return '%s(%s)' % (self.__class__.__name__, items)


class SimpleModel(Model):

    def build(self, dct):
        dct.update(self.__dict__)
        return dct

    def parse(self, dct):
        self.__dict__.update(dct)


class Database(SimpleModel):

    def __init__(self, hash, file, type, date):
        super(Database, self).__init__()
        self.hash = hash
        self.file = file
        self.type = type
        self.date = date

    def getHash(self):
        return self.hash

    def getFile(self):
        return self.file

    def getType(self):
        return self.type

    def getDate(self):
        return self.date


class Revision(SimpleModel):

    def __init__(self, hash, uuid, date):
        super(Revision, self).__init__()
        self.hash = hash
        self.uuid = uuid
        self.date = date

    def getHash(self):
        return self.hash

    def getUUID(self):
        return self.uuid

    def getDate(self):
        return self.date
