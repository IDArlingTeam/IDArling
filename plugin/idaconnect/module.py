MYPY = False
if MYPY:
    from .plugin import IDAConnect


class Module(object):
    """
    This is the base class of every module in the plugin.
    """

    def __init__(self, plugin):
        # type: (IDAConnect) -> None
        """
        Initialize the module.

        :param plugin: the plugin instance
        """
        self._plugin = plugin
        self._installed = False

    def install(self):
        # type: () -> bool
        """
         Install the module (called by the plugin).

         :return: if the module was properly installed
        """
        if self._installed:
            return False
        self._installed = True
        return self._install()

    def _install(self):
        # type: () -> bool
        """
        Install the module (called by the base class).

        :return: if the module was properly installed
        """
        raise NotImplementedError("_install() not implemented")

    def uninstall(self):
        # type: () -> bool
        """
        Uninstall the module (called by the plugin).

        :return: if the module was properly uninstalled
        """
        if not self._installed:
            return False
        self._installed = False
        return self._uninstall()

    def _uninstall(self):
        # type: () -> bool
        """
        Uninstall the module (called by the base class).

        :return: if the module properly uninstalled
        """
        raise NotImplementedError("_uninstall() not implemented")
