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
        pass  # raise NotImplementedError("build() not implemented")

    def parse(self, dct):
        pass  # raise NotImplementedError("parse() not implemented")

    def _dictRepr(self):
        return ', '.join(['%s=%s' % (key, repr(value)) for key, value in self
                          .__dict__.iteritems() if not key.startswith('_')])

    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__, self._dictRepr())


class Simple(object):

    def build(self, dct):
        super(Simple, self).build(dct)
        dct.update({key: value for key, value in self.__dict__.iteritems()
                    if not key.startswith('_')})
        return dct

    def parse(self, dct):
        super(Simple, self).build(dct)
        self.__dict__.update({key: value for key, value in dct.iteritems()
                              if not key.startswith('_')})
        return self


class SimpleModel(Simple, Model):
    pass


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

    def __init__(self, hash, uuid, date, bits):
        super(Revision, self).__init__()
        self.hash = hash
        self.uuid = uuid
        self.date = date
        self.bits = bits

    def getHash(self):
        return self.hash

    def getUUID(self):
        return self.uuid

    def getDate(self):
        return self.date

    def getBits(self):
        return self.bits
