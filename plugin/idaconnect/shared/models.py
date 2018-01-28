from mapper import Table, Field
from packets import Default


class Database(Default, Table):
    """
    The class representing a database.
    """
    __table__ = 'databases'

    hash = Field(str, notNull=True, unique=True)
    file = Field(str, notNull=True)
    type = Field(str, notNull=True)
    date = Field(str, notNull=True)

    def __init__(self, hash_, file_, type_, date):
        """
        Initialize a database.

        :param str hash_: the hash of the input file
        :param str file_: the name of the input file
        :param str type_: the type of the input file
        :param str date: the date of creation
        """
        super(Database, self).__init__()
        self.hash = hash_
        self.file = file_
        self.type = type_
        self.date = date


class Revision(Default, Table):
    """
    The class representing a revision.
    """
    __table__ = 'revisions'

    uuid = Field(str, notNull=True, unique=True)
    hash = Field(str, notNull=True)
    date = Field(str, notNull=True)
    bits = Field(str, notNull=True)

    def __init__(self, uuid, hash_, date, bits):
        """
        Initialize a revision.

        :param str uuid: the UUID of the revision
        :param str hash_: the hash of the input file
        :param str date: the date of creation
        :param str bits: the version (32/64) of IDA
        """
        super(Revision, self).__init__()
        self.uuid = uuid
        self.hash = hash_
        self.date = date
        self.bits = bits
