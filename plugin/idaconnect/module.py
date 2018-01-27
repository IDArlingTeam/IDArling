# -----------------------------------------------------------------------------
# Module
# -----------------------------------------------------------------------------


class Module(object):

    def __init__(self, plugin):
        # Require a plugin install
        self._plugin = plugin
        self._installed = False

    # -------------------------------------------------------------------------
    # Initialization
    # -------------------------------------------------------------------------

    def install(self):
        # Do not install twice
        if self._installed:
            return
        self._installed = True
        self._install()

    def _install(self):
        # Modules should implement this method
        raise NotImplementedError()

    # -------------------------------------------------------------------------
    # Termination
    # -------------------------------------------------------------------------

    def uninstall(self):
        # Do not uninstall twice
        if not self._installed:
            return
        self._installed = False
        return self._uninstall()

    def _uninstall(self):
        # Modules should implement this method
        raise NotImplementedError()
