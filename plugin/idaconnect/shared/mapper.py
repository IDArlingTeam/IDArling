import collections
import itertools
import operator


class Field(object):
    """
    An object representing a SQL column.
    """
    _TYPES = {int: 'integer', float: 'real', str: 'text'}
    _ORDER = itertools.count()

    def __init__(self, type, unique=False, notNull=False):
        """
        Initialize the field.

        :param type: the type of the field
        :param unique: are the column values unique
        :param notNull: can the column values be null
        """
        super(Field, self).__init__()
        assert type in Field._TYPES.keys(), "invalid type {}".format(type)
        self._type = type
        self._unique = unique
        self._notNull = notNull

        self.name = ''
        self.order = Field._ORDER.next()

    def __str__(self):
        """
        Return the textual representation of this field. It will be used to
        specify the columns' types of a table at its creation.

        :return: the representation
        """
        src = '{} {}'.format(self.name, Field._TYPES[self._type])
        src += ' unique' if self._unique else ''
        src += ' not null' if self._notNull else ''
        return src


class TableFactory(type):
    """
    The factory used to create table objects on-the-fly.
    """
    _TABLES = {}

    @staticmethod
    def __new__(mcs, name, bases, attrs):
        """
        Register a new table class in the factory.

        :param name: the name of the new class
        :param bases: the base classes of the new class
        :param attrs: the attributes of the new class
        :return: the newly created class
        """
        cls = super(TableFactory, mcs).__new__(mcs, name, bases, attrs)
        if cls.__table__ and cls.__table__ not in TableFactory._TABLES:
            cls.__fields__ = []
            for key, val in cls.__dict__.iteritems():
                if isinstance(val, Field):
                    val.name = key
                    cls.__fields__.append(val)
                    cls.__fields__.sort(key=operator.attrgetter('order'))
            TableFactory._TABLES[cls.__table__] = cls
        return cls

    @staticmethod
    def getClasses():
        """
        Get the table classes registered by the factory.

        :return: the classes
        """
        return TableFactory._TABLES


class Table(object):
    """
    An object representing a SQL table.
    """
    __metaclass__ = TableFactory

    __table__ = None
    __fields__ = []

    @staticmethod
    def fields(obj, ignore=None):
        """
        Get a dictionary of the fields and values of an object.

        :param obj: the object of interest
        :param ignore: a list of fields to ignore
        :return: the dictionary
        """
        if ignore is None:
            ignore = []
        fields = collections.OrderedDict()
        for key in obj.__fields__:
            if key.name not in ignore:
                fields[key.name] = obj.__dict__[key.name]
        return fields

    @classmethod
    def one(cls, **fields):
        """
        Get one object from the database matching the filter.

        :param fields: the fields to filter on
        :return: the object
        """
        return Mapper.getInstance().one(cls, **fields)

    @classmethod
    def all(cls, **fields):
        """
        Get all objects from the database matching the filter.

        :param fields: the fields to filter on
        :return: the objects
        """
        return Mapper.getInstance().all(cls, **fields)

    def __init__(self):
        """
        Instantiate a new table.
        """
        super(Table, self).__init__()
        assert self.__table__, "__table__ not implemented"
        self.id = 0  # will be set by the mapper

    def create(self):
        """
        Create a new object in the database.

        :return: the object
        """
        return Mapper.getInstance().create(self)

    def update(self):
        """
        Update the current object in the database.

        :return: the object
        """
        return Mapper.getInstance().update(self)

    def delete(self):
        """
        Delete the current object from the database.
        """
        Mapper.getInstance().delete(self)

    def __repr__(self):
        """
        Return a textual representation of the object. It will mainly be used
        for pretty-printing into the console.

        :return: the representation
        """
        s = ['{}={}'.format(k, v) for k, v in Table.fields(self).iteritems()]
        return '{}({})'.format(self.__class__.__name__, ', '.join(s))


class Mapper(object):
    """
    A singleton object that will do the mapping between instances and tables.
    """
    __instance__ = None

    @staticmethod
    def new(cls, **attrs):
        """
        Create a new instance of a table class.

        :param cls: the table class of the object
        :param attrs: the attributes of the object
        :return: the object
        """
        obj = Table.__new__(cls)
        Table.__init__(obj)
        for key, val in attrs.iteritems():
            setattr(obj, key, val)
        return obj

    @staticmethod
    def __new__(cls, *args, **kwargs):
        """
        Force only one instance of the mapper.
        """
        if cls.__instance__ is None:
            cls.__instance__ = super(Mapper, cls).__new__(cls)
        return cls.__instance__

    @classmethod
    def getInstance(cls):
        """
        Return the instance of the mapper.

        :return: the instance
        """
        return cls.__instance__

    def __init__(self, db):
        """
        Instantiate a new mapper.

        :param db: the connection to use
        """
        self._db = db

        # Create the tables if necessary
        for table, model in TableFactory.getClasses().iteritems():
            columns = [str(field) for field in Table.fields(model)]
            sql = 'create table if not exists {} (id integer primary key, {});'
            self.execute(sql.format(table, ', '.join(columns)))

    def one(self, cls, **fields):
        """
        Get one object from the database matching the filter.

        :param cls: the table class of the object
        :param fields: the fields to filter on
        :return: the object
        """
        row = self.get(cls, **fields).fetchone()
        if not row:
            raise ValueError("object does not exist")
        return self.new(cls, **row)

    def all(self, cls, **fields):
        """
        Get all objects from the database matching the filter.

        :param cls: the table class of the object
        :param fields: the fields to filter on
        :return: the objects
        """
        return [self.new(cls, **row) for row in self.get(cls, **fields)]

    def get(self, cls, **fields):
        """
        Get all rows from the database matching the filter.

        :param cls: the table class of the object
        :param fields: the fields to filter on
        :return: the cursor to the rows
        """
        fields = collections.OrderedDict([(key, val) for key, val
                                          in fields.iteritems() if val])
        if not fields:
            sql = 'select * from {}'.format(cls.__table__)
        else:
            cols = ', '.join(['{} = ?'.format(col) for col in fields.keys()])
            sql = 'select * from {} where {}'.format(cls.__table__, cols)
        return self.execute(sql, fields.values())

    def create(self, obj):
        """
        Create an object into the database.

        :param obj: the object to use
        :return: the same object
        """
        fields = Table.fields(obj, ['id'])
        keys = ', '.join(fields.keys())
        vals = ', '.join(['?' for _ in xrange(len(fields))])
        sql = 'insert into {} ({}) values ({})'
        sql = sql.format(obj.__table__, keys, vals)
        result = self.execute(sql, fields.values())
        obj.id = result.lastrowid
        return obj

    def update(self, obj):
        """
        Update an object in the database.

        :param obj: the object to use
        :return: the same object
        """
        fields = Table.fields(obj, ['id'])
        cols = ', '.join(['{} = ?'.format(col) for col in fields.keys()])
        sql = 'update {} set {} where id = ?'.format(obj.__table__, cols)
        self.execute(sql, fields.values() + [obj.id])
        return obj

    def delete(self, obj):
        """
        Delete an object from the database.

        :param obj: the object to use
        :return: the same object
        """
        sql = 'delete from {} where id = ?'.format(obj.__table__)
        self.execute(sql, [obj.id])

    def execute(self, sql, vals=None):
        """
        Execute a SQL request and return the result of the request.

        :param sql: the sql request
        :param vals: the values to use
        :return: a cursor to the results
        """
        if vals is None:
            vals = []
        print sql.replace('?', '{}').format(*vals)
        return self._db.execute(sql, vals)
