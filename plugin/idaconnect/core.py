class Core(object):

    def __init__(self, plugin):
        self._plugin = plugin
        self._installed = False

    def install(self):
        if self._installed:
            return
        self._install()
        self._installed = True

    def _install(self):
        raise NotImplementedError()

    def uninstall(self):
        if not self._installed:
            return
        self._uninstall()
        self._installed = False

    def _uninstall():
        raise NotImplementedError()
