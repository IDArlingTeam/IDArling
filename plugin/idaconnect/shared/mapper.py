import itertools
import operator
import sqlite3
from collections import OrderedDict as Dict


class Field(object):
    """
    An object representing a SQL column.
    """
    _TYPES = {int: 'integer', float: 'real', str: 'text'}
    _ORDER = itertools.count()

    def __init__(self, type_, unique=False, notNull=False):
        """
        Initialize the field.

        :param type type_: the type of the field
        :param bool unique: are the column values unique
        :param bool notNull: can the column values be null
        """
        super(Field, self).__init__()
        assert type_ in Field._TYPES.keys(), "invalid type {}".format(type)
        self.type = type_
        self.unique = unique
        self.notNull = notNull

        self.name = ''
        self.order = Field._ORDER.next()

    def __str__(self):
        """
        Return the textual representation of this field. It will be used to
        specify the columns' types of a table at its creation.

        :rtype: str
        """
        # noinspection PyTypeChecker
        descr = '{} {}'.format(self.name, Field._TYPES[self.type])
        descr += ' unique' if self.unique else ''
        descr += ' not null' if self.notNull else ''
        return descr


class TableFactory(type):
    """
    The factory used to create table objects on-the-fly.
    """
    _TABLES = {}

    @classmethod
    def getClasses(mcs):
        """
        Return the table classes registered by the factory.

        :rtype: dict[str, type[Table]]
        """
        return mcs._TABLES

    # noinspection PyUnresolvedReferences
    def __new__(mcs, name, bases, attrs):
        """
        Register a new table class in the factory.

        :param str name: the name of the new class
        :param tuple[type] bases: the base classes of the new class
        :param dict[str, object] attrs: the attributes of the new class
        :return: the newly created class
        :rtype: type[Table]
        """
        cls = super(TableFactory, mcs).__new__(mcs, name, bases, attrs)
        if cls.__table__ and cls.__table__ not in mcs._TABLES:
            cls.__fields__ = []
            for key, val in cls.__dict__.iteritems():
                if isinstance(val, Field):
                    val.name = key
                    cls.__fields__.append(val)
            cls.__fields__.sort(key=operator.attrgetter('order'))
            mcs._TABLES[cls.__table__] = cls
        return cls


class Table(object):
    """
    An object representing a SQL table.
    """
    __metaclass__ = TableFactory

    __table__ = None

    @staticmethod
    def fields(obj, ignore=None):
        """
        Get a dictionary of the fields and values of an object.

        :param Table|type[Table] obj: the object of interest
        :param list[str] ignore: a list of fields to ignore
        :rtype: dict[str, object]
        """
        if ignore is None:
            ignore = []
        fields = Dict()
        for key in obj.__fields__:
            if key.name not in ignore:
                fields[key.name] = obj.__dict__[key.name]
        return fields

    @classmethod
    def one(cls, **fields):
        """
        Get one object from the database matching the filter.

        :param dict[str, object] fields: the fields to filter on
        :rtype: Table
        """
        return Mapper.getInstance().one(cls, **fields)

    @classmethod
    def all(cls, **fields):
        """
        Get all objects from the database matching the filter.

        :param dict[str, object] fields: the fields to filter on
        :rtype: list[Table]
        """
        return Mapper.getInstance().all(cls, **fields)

    def __init__(self):
        """
        Instantiate a new table.
        """
        super(Table, self).__init__()
        assert self.__table__, "__table__ not implemented"
        self.id = 0  # will be filled by the mapper

    def create(self):
        """
        Create a new object in the database.

        :rtype: Table
        """
        return Mapper.getInstance().create(self)

    def update(self):
        """
        Update the current object in the database.

        :rtype: Table
        """
        return Mapper.getInstance().update(self)

    def delete(self):
        """
        Delete the current object from the database.

        :rtype: Table
        """
        return Mapper.getInstance().delete(self)

    def __repr__(self):
        """
        Return a textual representation of the object. It will mainly be used
        for pretty-printing into the console.

        :rtype: str
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

        :param type[Table] cls: the table class of the object
        :param dict[str, object] attrs: the attributes of the object
        :rtype: Table
        """
        obj = Table.__new__(cls)
        assert isinstance(obj, Table)
        Table.__init__(obj)
        for key, val in attrs.iteritems():
            setattr(obj, key, val)
        return obj

    @classmethod
    def getInstance(cls):
        """
        Return the instance of the mapper.

        :rtype: Mapper
        """
        return cls.__instance__

    def __new__(cls, *args, **kwargs):
        """
        Force only one instance of the mapper.

        :param list[object] args: the arguments
        :param dict[str, object] kwargs: the named arguments
        :rtype: type[Mapper]
        """
        if cls.__instance__ is None:
            # noinspection PyArgumentList
            cls.__instance__ = super(Mapper, cls).__new__(cls, *args, **kwargs)
        return cls.__instance__

    def __init__(self, db):
        """
        Instantiate a new mapper.

        :param sqlite3.Connection db: the connection to use
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

        :param type[Table] cls: the table class of the object
        :param dict[str, object] fields: the fields to filter on
        :rtype: Table
        """
        row = self.get(cls, **fields).fetchone()
        assert isinstance(row, sqlite3.Row)
        if not row:
            return ValueError("object does not exist")
        # noinspection PyArgumentList
        return self.new(cls, **row)

    def all(self, cls, **fields):
        """
        Get all objects from the database matching the filter.

        :param type[Table] cls: the table class of the object
        :param dict[str, object] fields: the fields to filter on
        :rtype: list[Table]
        """
        return [self.new(cls, **row) for row in self.get(cls, **fields)]

    def get(self, cls, **fields):
        """
        Get all rows from the database matching the filter.

        :param type[Table] cls: the table class of the object
        :param dict[str, object] fields: the fields to filter on
        :rtype: sqlite3.Cursor
        """
        assert isinstance(cls, Table.__class__)
        fields = Dict([(key, val) for key, val in fields.iteritems() if val])
        if not fields:
            sql = 'select * from {}'.format(cls.__table__)
        else:
            cols = ', '.join(['{} = ?'.format(col) for col in fields.keys()])
            sql = 'select * from {} where {}'.format(cls.__table__, cols)
        return self.execute(sql, fields.values())

    def create(self, obj):
        """
        Create an object into the database.

        :param Table obj: the object to use
        :rtype: Table
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

        :param Table obj: the object to use
        :rtype: Table
        """
        fields = Table.fields(obj, ['id'])
        cols = ', '.join(['{} = ?'.format(col) for col in fields.keys()])
        sql = 'update {} set {} where id = ?'.format(obj.__table__, cols)
        self.execute(sql, fields.values() + [obj.id])
        return obj

    def delete(self, obj):
        """
        Delete an object from the database.

        :param Table obj: the object to use
        :rtype: Table
        """
        sql = 'delete from {} where id = ?'.format(obj.__table__)
        self.execute(sql, [obj.id])

    def execute(self, sql, vals=None):
        """
        Execute a SQL request and return the result of the request.

        :param str sql: the sql request
        :param list[object] vals: the values to use
        :rtype: sqlite3.Cursor
        """
        if vals is None:
            vals = []
        print sql.replace('?', '{}').format(*vals)
        return self._db.execute(sql, vals)
