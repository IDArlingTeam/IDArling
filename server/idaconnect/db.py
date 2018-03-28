# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
import json
import sqlite3

from twisted.enterprise import adbapi

from utils import localFile
from shared.models import Repository, Branch
from shared.packets import Default, DefaultEvent


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
                'tick integer',
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

    def insertEvent(self, client, event):
        """
        Inserts a new event into the database.

        :param client: the client
        :param event: the event
        :return: a deferred triggered when the operation is done
        """
        dct = DefaultEvent.attrs(event.__dict__)
        return self._insert('events', {
            'hash': client.repo,
            'uuid': client.branch,
            'tick': dct.pop('tick'),
            'dict': json.dumps(dct)
        })

    def selectEvents(self, hash, uuid, tick):
        """
        Get all events sent after the given ticks count.

        :param hash: the repository
        :param uuid: the branch
        :param tick: the ticks count
        :return: the list of events
        """
        def fetchRows(txn):
            sql = 'select * from events where hash = ? and uuid = ? ' \
                  'and tick > ? order by tick asc;'
            txn.execute(sql, [hash, uuid, tick])
            events = []
            for result in txn.fetchall():
                dct = json.loads(result['dict'])
                dct['tick'] = result['tick']
                events.append(DefaultEvent.new(dct))
            return events
        return self._conn.runInteraction(fetchRows)

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
        vals = ', '.join(['?'] * len(fields))
        return self._conn.runOperation(sql.format(table, keys, vals),
                                       fields.values())
