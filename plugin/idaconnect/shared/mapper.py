import operator
import itertools
from collections import OrderedDict as Dict

# -----------------------------------------------------------------------------
# Field
# -----------------------------------------------------------------------------


class Field(object):
    _TYPES = {int: 'integer', float: 'real', str: 'text'}
    _ORDER = itertools.count()

    def __init__(self, type, unique=False, notNull=False):
        super(Field, self).__init__()
        assert type in Field._TYPES.keys(), "invalid type {}".format(type)
        self.type = type
        self.unique = unique
        self.notNull = notNull

        self.name = ''
        self.order = Field._ORDER.next()

    def __str__(self):
        str = '{} {}'.format(self.name, Field._TYPES[self.type])
        str += ' unique' if self.unique else ''
        str += ' not null' if self.notNull else ''
        return str

# -----------------------------------------------------------------------------
# Table
# -----------------------------------------------------------------------------


class TableFactory(type):
    _TABLES = {}

    @classmethod
    def getClasses(mcs):
        return mcs._TABLES

    def __new__(mcs, name, bases, attrs):
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
    __metaclass__ = TableFactory

    __table__ = None

    @staticmethod
    def fields(obj, ignore=[]):
        fields = Dict()
        for key in obj.__fields__:
            if key.name not in ignore:
                fields[key.name] = obj.__dict__[key.name]
        return fields

    @classmethod
    def one(cls, **fields):
        return Mapper.getInstance().one(cls, **fields)

    @classmethod
    def all(cls, **fields):
        return Mapper.getInstance().all(cls, **fields)

    def __init__(self):
        super(Table, self).__init__()
        assert self.__table__, "__table__ not implemented"

    def create(self):
        return Mapper.getInstance().create(self)

    def update(self):
        return Mapper.getInstance().update(self)

    def delete(self):
        return Mapper.getInstance().delete(self)

    def __repr__(self):
        s = ['{}={}'.format(k, v) for k, v in Table.fields(self).iteritems()]
        return '{}({})'.format(self.__class__.__name__, ', '.join(s))

# -----------------------------------------------------------------------------
# Mapper
# -----------------------------------------------------------------------------


class Mapper(object):
    __instance__ = None

    @classmethod
    def getInstance(cls):
        return cls.__instance__

    def __new__(cls, *args, **kwargs):
        if cls.__instance__ is None:
            cls.__instance__ = super(Mapper, cls).__new__(cls, *args, **kwargs)
        return cls.__instance__

    def __init__(self, db):
        self._db = db

        for table, model in TableFactory.getClasses().iteritems():
            columns = [str(field) for field in model.__fields__]
            sql = 'create table if not exists {} (id integer primary key, {});'
            self.execute(sql.format(table, ', '.join(columns)))

    def one(self, cls, **fields):
        row = self.get(cls, **fields).fetchone()
        if not row:
            return ValueError("object does not exist")
        return self.new(cls, **row)

    def all(self, cls, **fields):
        return [self.new(cls, **row) for row in self.get(cls, **fields)]

    def get(self, cls, **fields):
        fields = Dict([(key, val) for key, val in fields.iteritems() if val])
        if not fields:
            sql = 'select * from {}'.format(cls.__table__)
        else:
            cols = ', '.join(['{} = ?'.format(col) for col in fields.keys()])
            sql = 'select * from {} where {}'.format(cls.__table__, cols)
        return self.execute(sql, fields.values())

    def new(self, cls, **attrs):
        obj = Table.__new__(cls)
        Table.__init__(obj)
        for key, val in attrs.iteritems():
            setattr(obj, key, val)
        return obj

    def create(self, obj):
        fields = Table.fields(obj, ['id'])
        keys = ', '.join(fields.keys())
        vals = ', '.join(['?' for _ in xrange(len(fields))])
        sql = 'insert into {} ({}) values ({})'
        sql = sql.format(obj.__table__, keys, vals)
        result = self.execute(sql, fields.values())
        obj.id = result.lastrowid
        return obj

    def update(self, obj):
        fields = Table.fields(obj, ['id'])
        cols = ', '.join(['{} = ?'.format(col) for col in fields.keys()])
        sql = 'update {} set {} where id = ?'.format(obj.__table__, cols)
        self.execute(sql, fields.values() + [obj.id])
        return obj

    def delete(self, obj):
        sql = 'delete from {} where id = ?'.format(obj.__table__)
        self.execute(sql, [obj.id])

    def execute(self, sql, vals=[]):
        print sql.replace('?', '{}').format(*vals)
        return self._db.execute(sql, vals)
