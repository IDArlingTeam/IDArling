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

from .models import Branch, Repository
from .packets import Default, DefaultEvent


class Database(object):
    """
    This object is used to access the SQL database used by the server. It
    also defines some utility methods. Currently, only SQLite3 is implemented.
    """

    def __init__(self, dbpath):
        self._conn = sqlite3.connect(dbpath, check_same_thread=False)
        self._conn.isolation_level = None  # No need to commit
        self._conn.row_factory = sqlite3.Row  # Use Row objects

    def initialize(self):
        """Create all the default tables."""
        self._create(
            "repos",
            [
                "name text not null",
                "hash text not null",
                "file text not null",
                "type text not null",
                "date text not null",
                "primary key (name)",
            ],
        )
        self._create(
            "branches",
            [
                "repo text not null",
                "name text not null",
                "date text not null",
                "foreign key(repo) references repos(name)",
                "primary key(repo, name)",
            ],
        )
        self._create(
            "events",
            [
                "repo text not null",
                "branch text not null",
                "tick integer not null",
                "dict text not null",
                "foreign key(repo) references repos(name)",
                "foreign key(repo, branch) references branches(repo, name)",
                "primary key(repo, branch, tick)",
            ],
        )

    def insert_repo(self, repo):
        """Insert a new repository into the database."""
        self._insert("repos", Default.attrs(repo.__dict__))

    def select_repo(self, name):
        """Select the repository with the given name."""
        objects = self.select_repos(name, 1)
        return objects[0] if objects else None

    def select_repos(self, name=None, limit=None):
        """Select the repositories with the given name."""
        results = self._select("repos", {"name": name}, limit)
        return [Repository(**result) for result in results]

    def insert_branch(self, branch):
        """Insert a new branch into the database."""
        attrs = Default.attrs(branch.__dict__)
        attrs.pop("tick")
        self._insert("branches", attrs)

    def select_branch(self, repo, name):
        """Select the branch with the given repo and name."""
        objects = self.select_branches(repo, name, 1)
        return objects[0] if objects else None

    def select_branches(self, repo=None, name=None, limit=None):
        """Select the branches with the given repo and name."""
        results = self._select("branches", {"repo": repo, "name": name}, limit)
        return [Branch(**result) for result in results]

    def insert_event(self, client, event):
        """Insert a new event into the database."""
        dct = DefaultEvent.attrs(event.__dict__)
        self._insert(
            "events",
            {
                "repo": client.repo,
                "branch": client.branch,
                "tick": event.tick,
                "dict": json.dumps(dct),
            },
        )

    def select_events(self, repo, branch, tick):
        """Get all events sent after the given tick count."""
        c = self._conn.cursor()
        sql = "select * from events where repo = ? and branch = ?"
        sql += "and tick > ? order by tick asc;"
        c.execute(sql, [repo, branch, tick])
        events = []
        for result in c.fetchall():
            dct = json.loads(result["dict"])
            dct["tick"] = result["tick"]
            events.append(DefaultEvent.new(dct))
        return events

    def last_tick(self, repo, branch):
        """Get the last tick of the specified repo and branch."""
        c = self._conn.cursor()
        sql = "select tick from events where repo = ? and branch = ? "
        sql += "order by tick desc limit 1;"
        c.execute(sql, [repo, branch])
        result = c.fetchone()
        return result["tick"] if result else 0

    def _create(self, table, cols):
        """Create a table with the given name and columns."""
        c = self._conn.cursor()
        sql = "create table if not exists {} ({});"
        c.execute(sql.format(table, ", ".join(cols)))

    def _select(self, table, fields, limit=None):
        """Select the rows of a table matching the given values."""
        c = self._conn.cursor()
        sql = "select * from {}".format(table)
        fields = {key: val for key, val in fields.items() if val}
        if len(fields):
            cols = ["{} = ?".format(col) for col in fields.keys()]
            sql = (sql + " where {}").format(" and ".join(cols))
        sql += " limit {};".format(limit) if limit else ";"
        c.execute(sql, list(fields.values()))
        return c.fetchall()

    def _insert(self, table, fields):
        """Insert a row into a table with the given values."""
        c = self._conn.cursor()
        sql = "insert into {} ({}) values ({});"
        keys = ", ".join(fields.keys())
        vals = ", ".join(["?"] * len(fields))
        c.execute(sql.format(table, keys, vals), list(fields.values()))
