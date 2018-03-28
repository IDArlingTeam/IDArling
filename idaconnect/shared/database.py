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

from .models import Repository, Branch
from .packets import Default, DefaultEvent


class Database(object):
    """
    An utility object used by the server, that be used to query
    asynchronously the underling SQL database.
    """

    def __init__(self, dbpath):
        """
        Initialize the database wrapper.

        :param dbpath: the database path
        """
        self._conn = sqlite3.connect(dbpath, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row

    def initialize(self):
        """
        Creates all the tables used by the wrapper.
        """
        self._create('repos', [
            'hash text primary key',
            'file string',
            'type string',
            'date string'
        ])
        self._create('branches', [
            'uuid text primary key',
            'hash text',
            'date text',
            'bits integer',
            'foreign key(hash) references repos(hash)'
        ])
        self._create('events', [
            'hash text',
            'uuid text',
            'tick integer',
            'dict text',
            'foreign key(hash) references repos(hash)',
            'foreign key(uuid) references branches(uuid)'
        ])

    def insert_repo(self, repo):
        """
        Inserts a new repository into the database.

        :param repo: the repository
        """
        self._insert('repos', Default.attrs(repo.__dict__))

    def select_repo(self, hash):
        """
        Selects the repository with the given hash.

        :param hash: the hash, or None if no filtering
        :return: the repository or None
        """
        objects = self.select_repos(hash, 1)
        return objects[0] if objects else None

    def select_repos(self, hash, limit=None):
        """
        Selects the repositories with the given hash.

        :param hash: the hash, or None if no filtering
        :param limit: the number of results to return, or None
        :return: the repositories
        """
        results = self._select('repos', {'hash': hash}, limit)
        return [Repository(*result) for result in results]

    def insert_branch(self, branch):
        """
        Inserts a new branch into the database.

        :param branch: the branch
        """
        self._insert('branches', Default.attrs(branch.__dict__))

    def select_branch(self, uuid, hash):
        """
        Selects the branch with the given uuid and hash.

        :param uuid: the uuid, or None if no filtering
        :param hash: the hash, or None if no filtering
        :return: the branch or None
        """
        objects = self.select_branches(uuid, hash, 1)
        return objects[0] if objects else None

    def select_branches(self, uuid, hash, limit=None):
        """
        Selects the branches with the given uuid and hash.

        :param uuid: the uuid, or None if no filtering
        :param hash: the hash, or None if no filtering
        :param limit: the number of results to return, or None
        :return: the branches
        """
        results = self._select('branches', {'uuid': uuid, 'hash': hash}, limit)
        return [Branch(*result) for result in results]

    def insert_event(self, client, event):
        """
        Inserts a new event into the database.

        :param client: the client
        :param event: the event
        """
        dct = DefaultEvent.attrs(event.__dict__)
        self._insert('events', {
            'hash': client.repo,
            'uuid': client.branch,
            'tick': dct.pop('tick'),
            'dict': json.dumps(dct)
        })

    def select_events(self, hash, uuid, tick):
        """
        Get all events sent after the given ticks count.

        :param hash: the repository
        :param uuid: the branch
        :param tick: the ticks count
        :return: the events
        """
        c = self._conn.cursor()
        sql = 'select * from events where hash = ? and uuid = ? ' \
              'and tick > ? order by tick asc;'
        c.execute(sql, [hash, uuid, tick])
        events = []
        for result in c.fetchall():
            dct = json.loads(result['dict'])
            dct['tick'] = result['tick']
            events.append(DefaultEvent.new(dct))
        return events

    def _create(self, table, cols):
        """
        Creates a table with the given name and columns.

        :param table: the table name
        :param cols: the columns
        """
        c = self._conn.cursor()
        sql = 'create table if not exists {} ({});'
        c.execute(sql.format(table, ', '.join(cols)))

    def _select(self, table, fields, limit=None):
        """
        Selects the rows of a table matching the given values.

        :param table: the table name
        :param fields: the fields and values to match
        :param limit: the number of results to return
        :return: the selected rows
        """
        c = self._conn.cursor()
        sql = 'select * from {}'.format(table)
        fields = {key: val for key, val in fields.items() if val}
        if len(fields):
            cols = ['{} = ?'.format(col) for col in fields.keys()]
            sql = (sql + ' where {}').format(' and '.join(cols))
        sql += ' limit {};'.format(limit) if limit else ';'
        c.execute(sql, list(fields.values()))
        return c.fetchall()

    def _insert(self, table, fields):
        """
        Inserts a row into a table with the given values.

        :param table: the table name
        :param fields: the field and values
        """
        c = self._conn.cursor()
        sql = 'insert into {} ({}) values ({});'
        keys = ', '.join(fields.keys())
        vals = ', '.join(['?'] * len(fields))
        c.execute(sql.format(table, keys, vals), list(fields.values()))
