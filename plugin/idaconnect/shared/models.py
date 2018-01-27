from mapper import Table, Field
from packets import Default

# -----------------------------------------------------------------------------
# Database
# -----------------------------------------------------------------------------


class Database(Default, Table):
    __table__ = 'databases'

    hash = Field(str, notNull=True, unique=True)
    file = Field(str, notNull=True)
    type = Field(str, notNull=True)
    date = Field(str, notNull=True)

    def __init__(self, hash, file, type, date):
        super(Database, self).__init__()
        self.hash = hash
        self.file = file
        self.type = type
        self.date = date

# -----------------------------------------------------------------------------
# Revision
# -----------------------------------------------------------------------------


class Revision(Default, Table):
    __table__ = 'revisions'

    uuid = Field(str, notNull=True, unique=True)
    hash = Field(str, notNull=True)
    date = Field(str, notNull=True)
    bits = Field(str, notNull=True)

    def __init__(self, uuid, hash, date, bits):
        super(Revision, self).__init__()
        self.uuid = uuid
        self.hash = hash
        self.date = date
        self.bits = bits
