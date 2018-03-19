import sqlite3

from twisted.enterprise import adbapi

from utils import localFile
from shared.models import Repository, Branch
from shared.packets import Default


class Database(object):
    """
    An utility object used by the server, that be used to query
    asynchronously the underling SQL database.
    """

    def __init__(self):
        """
        Initialize the database wrapper.
        """
        def setRowFactory(db):
            db.row_factory = sqlite3.Row
        self._conn = adbapi.ConnectionPool('sqlite3', localFile('database.db'),
                                           check_same_thread=False,
                                           cp_openfun=setRowFactory)

    def initialize(self):
        """
        Creates all the tables used by the wrapper.

        :return: a deferred triggered when initialization is done
        """
        def createTables(txn):
            Database._create(txn, 'repos', [
                'hash text primary key',
                'file string',
                'type string',
                'date string'
            ])
            Database._create(txn, 'branches', [
                'uuid text primary key',
                'hash text',
                'date text',
                'bits integer',
                'foreign key(hash) references repos(hash)'
            ])
            Database._create(txn, 'events', [
                'hash text',
                'uuid text',
                'dict text',
                'foreign key(hash) references repos(hash)',
                'foreign key(uuid) references branches(uuid)'
            ])
        return self._conn.runInteraction(createTables)

    def insertRepo(self, repo):
        """
        Inserts a new repository into the database.

        :param repo: the repository
        :return: a deferred triggered when the operation is done
        """
        return self._insert('repos', Default.attrs(repo.__dict__))

    def selectRepo(self, hash):
        """
        Selects the repository with the given hash.

        :param hash: the hash, or None if no filtering
        :return: a deferred triggered when the operation is done
        """
        d = self.selectRepos(hash, 1)

        def unpackFirst(objects):
            return objects[0] if objects else None
        return d.addCallback(unpackFirst)

    def selectRepos(self, hash, limit=None):
        """
        Selects the repositories with the given hash.

        :param hash: the hash, or None if no filtering
        :param limit: the number of results to return, or None
        :return: a deferred triggered when the operation is done
        """
        def fetchRows(txn):
            results = Database._select(txn, 'repos', {'hash': hash}, limit)
            return [Repository(*result) for result in results]
        return self._conn.runInteraction(fetchRows)

    def insertBranch(self, branch):
        """
        Inserts a new branch into the database.

        :param branch: the branch
        :return: a deferred triggered when the operation is done
        """
        return self._insert('branches', Default.attrs(branch.__dict__))

    def selectBranch(self, uuid, hash):
        """
        Selects the branch with the given uuid and hash.

        :param uuid: the uuid, or None if no filtering
        :param hash: the hash, or None if no filtering
        :return: a deferred triggered when the operation is done
        """
        d = self.selectBranches(uuid, hash, 1)

        def unpackFirst(objects):
            return objects[0] if objects else None
        return d.addCallback(unpackFirst)

    def selectBranches(self, uuid, hash, limit=None):
        """
        Selects the branches with the given uuid and hash.

        :param uuid: the uuid, or None if no filtering
        :param hash: the hash, or None if no filtering
        :param limit: the number of results to return, or None
        :return: a deferred triggered when the operation is done
        """
        def fetchRows(txn):
            results = Database._select(txn, 'branches', {'uuid': uuid,
                                                         'hash': hash}, limit)
            return [Branch(*result) for result in results]
        return self._conn.runInteraction(fetchRows)

    def insertEvent(self, event):
        """
        Inserts a new branch into the database.

        :param event: the event
        :return: a deferred triggered when the operation is done
        """
        return self._insert('events', Default.attrs(event.__dict__))

    @staticmethod
    def _create(txn, table, cols):
        """
        Creates a table with the given name and columns.

        :param txn: the transaction
        :param table: the table name
        :param cols: the columns
        """
        sql = 'create table if not exists {} ({});'
        txn.execute(sql.format(table, ', '.join(cols)))

    @staticmethod
    def _select(txn, table, fields, limit=None):
        """
        Selects the rows of a table matching the given values.

        :param txn: the transaction
        :param table: the table name
        :param fields: the fields and values to match
        :param limit: the number of results to return
        :return: the selected rows
        """
        sql = 'select * from {}'.format(table)
        fields = {key: val for key, val in fields.iteritems() if val}
        if len(fields):
            cols = ['{} = ?'.format(col) for col in fields.keys()]
            sql = (sql + ' where {}').format(' and '.join(cols))
        sql += ' limit {};'.format(limit) if limit else ';'
        txn.execute(sql, fields.values())
        return txn.fetchall()

    def _insert(self, table, fields):
        """
        Inserts a row into a table with the given values.

        :param table: the table name
        :param fields: the field and values
        :return: a deferred trigger when the operation is done
        """
        sql = 'insert into {} ({}) values ({});'
        keys = ', '.join(fields.keys())
        vals = ', '.join(['?' for _ in xrange(len(fields))])
        return self._conn.runOperation(sql.format(table, keys, vals),
                                       fields.values())
