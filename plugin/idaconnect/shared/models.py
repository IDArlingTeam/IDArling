import json

from mapper import Field, Table, TableFactory
from packets import Default, Event, EventFactory


class DefaultTable(Default, Table):

    def build(self, dct):
        self.buildDefault(dct)
        return dct

    def parse(self, dct):
        self.parseDefault(dct)
        return self


class Repository(DefaultTable):
    """
    The class representing a repository.
    """
    __table__ = 'repositories'

    hash = Field(str, notNull=True, unique=True)
    file = Field(str, notNull=True)
    type = Field(str, notNull=True)
    date = Field(str, notNull=True)

    def __init__(self, hash, file, type, date):
        """
        Initialize a repository.

        :param hash: the hash of the input file
        :param file: the name of the input file
        :param type: the type of the input file
        :param date: the date of creation
        """
        super(Repository, self).__init__()
        self.hash = hash
        self.file = file
        self.type = type
        self.date = date


class Branch(DefaultTable):
    """
    The class representing a branch.
    """
    __table__ = 'branches'

    uuid = Field(str, notNull=True, unique=True)
    hash = Field(str, notNull=True)
    date = Field(str, notNull=True)
    bits = Field(int, notNull=True)

    def __init__(self, uuid, hash, date, bits):
        """
        Initialize a branch.

        :param uuid: the UUID of the branch
        :param hash: the hash of the input file
        :param date: the date of creation
        :param bits: the bitness (32/64) of IDA
        """
        super(Branch, self).__init__()
        self.uuid = uuid
        self.hash = hash
        self.date = date
        self.bits = bits


class EventTableFactory(EventFactory, TableFactory):
    """
    A meta class for subclassing Event and Table at the same time.
    """
    pass


class EventTable(Event, Table):
    """
    A base class for subclassing Event and Table at the same time.
    """
    __metaclass__ = EventTableFactory


class AbstractEvent(EventTable):
    """
    A class to represent events as seen by the server. The server relays the
    events to the interested clients, it doesn't know to interpret them.
    """
    __event__ = 'all'
    __table__ = 'events'

    hash = Field(str, notNull=True)
    uuid = Field(str, notNull=True)
    dict = Field(str, notNull=True)

    def buildEvent(self, dct):
        dct.update(json.loads(self.dict))

    def parseEvent(self, dct):
        self.dict = json.dumps(dct)
