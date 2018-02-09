from .models import Repository, Branch
from .packets import (Command, DefaultCommand, ParentCommand,
                      Query as IQuery, Reply as IReply, Container)


class GetRepositories(ParentCommand):
    __command__ = 'get_repos'

    class Query(IQuery, DefaultCommand):

        def __init__(self, hash=None):
            super(GetRepositories.Query, self).__init__()
            self.hash = hash

    class Reply(IReply, Command):

        def __init__(self, query, repos):
            super(GetRepositories.Reply, self).__init__(query)
            self.repos = repos

        def buildCommand(self, dct):
            dct['repos'] = [repo.build(dict()) for repo in self.repos]

        def parseCommand(self, dct):
            self.repos = [Repository.new(repo) for repo in dct['repos']]


class GetBranches(ParentCommand):
    __command__ = 'get_branches'

    class Query(IQuery, DefaultCommand):

        def __init__(self, hash=None, uuid=None):
            super(GetBranches.Query, self).__init__()
            self.hash = hash
            self.uuid = uuid

    class Reply(IReply, Command):

        def __init__(self, query, branches):
            super(GetBranches.Reply, self).__init__(query)
            self.branches = branches

        def buildCommand(self, dct):
            dct['branches'] = [br.build(dict()) for br in self.branches]

        def parseCommand(self, dct):
            self.branches = [Branch.new(br) for br in dct['branches']]


class NewRepository(ParentCommand):
    __command__ = 'new_repo'

    class Query(IQuery, Command):

        def __init__(self, repo):
            super(NewRepository.Query, self).__init__()
            self.repo = repo

        def buildCommand(self, dct):
            self.repo.build(dct['repo'])

        def parseCommand(self, dct):
            self.repo = Repository.new(dct['repo'])

    class Reply(IReply, Command):
        pass


class NewBranch(ParentCommand):
    __command__ = 'new_branch'

    class Query(IQuery, Command):

        def __init__(self, branch):
            super(NewBranch.Query, self).__init__()
            self.branch = branch

        def buildCommand(self, dct):
            self.branch.build(dct['branch'])

        def parseCommand(self, dct):
            self.branch = Branch.new(dct['branch'])

    class Reply(IReply, Command):
        pass


class UploadDatabase(ParentCommand):
    __command__ = 'upload_db'

    class Query(IQuery, Container, DefaultCommand):

        def __init__(self, hash, uuid):
            super(UploadDatabase.Query, self).__init__()
            self.hash = hash
            self.uuid = uuid

    class Reply(IReply, Command):
        pass


class DownloadDatabase(ParentCommand):
    __command__ = 'download_db'

    class Query(IQuery, DefaultCommand):

        def __init__(self, hash, uuid):
            super(DownloadDatabase.Query, self).__init__()
            self.hash = hash
            self.uuid = uuid

    class Reply(IReply, Container, Command):
        pass
