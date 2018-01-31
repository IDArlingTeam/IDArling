from mapper import Field, Table
from packets import Default


class DefaultTable(Default, Table):

    def build(self, dct):
        self.buildDefault(dct)
        return dct

    def parse(self, dct):
        self.parseDefault(dct)
        return self


class Database(DefaultTable):
    """
    The class representing a database.
    """
    __table__ = 'databases'

    hash = Field(str, notNull=True, unique=True)
    file = Field(str, notNull=True)
    type = Field(str, notNull=True)
    date = Field(str, notNull=True)

    def __init__(self, hash, file, type, date):
        """
        Initialize a database.

        :param hash: the hash of the input file
        :param file: the name of the input file
        :param type: the type of the input file
        :param date: the date of creation
        """
        super(Database, self).__init__()
        self.hash = hash
        self.file = file
        self.type = type
        self.date = date


class Revision(DefaultTable):
    """
    The class representing a revision.
    """
    __table__ = 'revisions'

    uuid = Field(str, notNull=True, unique=True)
    hash = Field(str, notNull=True)
    date = Field(str, notNull=True)
    bits = Field(str, notNull=True)

    def __init__(self, uuid, hash, date, bits):
        """
        Initialize a revision.

        :param uuid: the UUID of the revision
        :param hash: the hash of the input file
        :param date: the date of creation
        :param bits: the version (32/64) of IDA
        """
        super(Revision, self).__init__()
        self.uuid = uuid
        self.hash = hash
        self.date = date
        self.bits = bits
