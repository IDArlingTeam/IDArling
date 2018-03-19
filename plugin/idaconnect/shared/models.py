import json

from packets import Default, Event


class Model(Default):
    """
    An object that can be serialized before being sent over the network,
    but that can also be saved into the server SQL database.
    """

    def build(self, dct):
        self.buildDefault(dct)
        return dct

    def parse(self, dct):
        self.parseDefault(dct)
        return self

    def __repr__(self):
        """
        Return a textual representation of the object. It will mainly be used
        for pretty-printing into the console.
        :return: the representation
        """
        attrs = ', '.join(['{}={}'.format(key, val) for key, val in
                           Default.attrs(self.__dict__).iteritems()])
        return '{}({})'.format(self.__class__.__name__, attrs)


class Repository(Model):
    """
    The class representing a repository.
    """

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


class Branch(Model):
    """
    The class representing a branch.
    """

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


class AbstractEvent(Event, Model):
    """
    A class to represent events as seen by the server. The server relays the
    events to the interested clients, it doesn't know to interpret them.
    """

    def __init__(self, hash, uuid, dict):
        super(AbstractEvent, self).__init__()
        self.hash = hash
        self.uuid = uuid
        self.dict = dict

    def buildEvent(self, dct):
        dct.update(json.loads(self.dict))

    def parseEvent(self, dct):
        self.dict = json.dumps(dct)
