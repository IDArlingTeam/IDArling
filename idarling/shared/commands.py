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
from .models import Database, Project
from .packets import (
    Command,
    Container,
    DefaultCommand,
    ParentCommand,
    Query as IQuery,
    Reply as IReply,
)


class GetProjects(ParentCommand):
    __command__ = "get_projects"

    class Query(IQuery, DefaultCommand):
        pass

    class Reply(IReply, Command):
        def __init__(self, query, projects):
            super(GetProjects.Reply, self).__init__(query)
            self.projects = projects

        def build_command(self, dct):
            dct["projects"] = [project.build({}) for project in self.projects]

        def parse_command(self, dct):
            self.projects = [
                Project.new(project) for project in dct["projects"]
            ]


class GetDatabases(ParentCommand):
    __command__ = "get_databases"

    class Query(IQuery, DefaultCommand):
        def __init__(self, project):
            super(GetDatabases.Query, self).__init__()
            self.project = project

    class Reply(IReply, Command):
        def __init__(self, query, databases):
            super(GetDatabases.Reply, self).__init__(query)
            self.databases = databases

        def build_command(self, dct):
            dct["databases"] = [
                database.build({}) for database in self.databases
            ]

        def parse_command(self, dct):
            self.databases = [
                Database.new(database) for database in dct["databases"]
            ]


class NewProject(ParentCommand):
    __command__ = "new_project"

    class Query(IQuery, Command):
        def __init__(self, project):
            super(NewProject.Query, self).__init__()
            self.project = project

        def build_command(self, dct):
            self.project.build(dct["project"])

        def parse_command(self, dct):
            self.project = Project.new(dct["project"])

    class Reply(IReply, Command):
        pass


class NewDatabase(ParentCommand):
    __command__ = "new_database"

    class Query(IQuery, Command):
        def __init__(self, database):
            super(NewDatabase.Query, self).__init__()
            self.database = database

        def build_command(self, dct):
            self.database.build(dct["database"])

        def parse_command(self, dct):
            self.database = Database.new(dct["database"])

    class Reply(IReply, Command):
        pass


class UpdateFile(ParentCommand):
    __command__ = "update_file"

    class Query(IQuery, Container, DefaultCommand):
        def __init__(self, project, database):
            super(UpdateFile.Query, self).__init__()
            self.project = project
            self.database = database

    class Reply(IReply, Command):
        pass


class DownloadFile(ParentCommand):
    __command__ = "download_file"

    class Query(IQuery, DefaultCommand):
        def __init__(self, project, database):
            super(DownloadFile.Query, self).__init__()
            self.project = project
            self.database = database

    class Reply(IReply, Container, Command):
        pass


class Subscribe(DefaultCommand):
    __command__ = "subscribe"

    def __init__(self, project, database, tick, name, color, ea, silent=True):
        super(Subscribe, self).__init__()
        self.project = project
        self.database = database
        self.tick = tick
        self.name = name
        self.color = color
        self.ea = ea
        self.silent = silent


class Unsubscribe(DefaultCommand):
    __command__ = "unsubscribe"

    def __init__(self, name, silent=True):
        super(Unsubscribe, self).__init__()
        self.name = name
        self.silent = silent


class UpdateCursors(DefaultCommand):
    __command__ = "update_cursors"

    def __init__(self, name, ea, color):
        super(UpdateCursors, self).__init__()
        self.name = name
        self.ea = ea
        self.color = color


class UserRenamed(DefaultCommand):
    __command__ = "user_renamed"

    def __init__(self, old_name, new_name):
        super(UserRenamed, self).__init__()
        self.old_name = old_name
        self.new_name = new_name


class UserColorChanged(DefaultCommand):
    __command__ = "user_color_changed"

    def __init__(self, name, old_color, new_color):
        super(UserColorChanged, self).__init__()
        self.name = name
        self.old_color = old_color
        self.new_color = new_color


class InviteTo(DefaultCommand):
    __command__ = "invite_to"

    def __init__(self, name, loc):
        super(InviteTo, self).__init__()
        self.name = name
        self.loc = loc
