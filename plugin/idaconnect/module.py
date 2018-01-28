class Module(object):
    """
    This is the base class of every module in the plugin.
    """

    def __init__(self, plugin):
        """
        Initialize the module.

        :param IDAConnect plugin: the plugin instance
        """
        self._plugin = plugin
        self._installed = False

    def install(self):
        """
         Install the module (called by the plugin).
        """
        if self._installed:
            return
        self._installed = True
        self._install()

    def _install(self):
        """
        Module subclasses should implement this method.

        :return: was the module properly installed
        :rtype: bool
        """
        raise NotImplementedError("_install() not implemented")

    def uninstall(self):
        """
        Uninstall the module (called by the plugin).
        """
        if not self._installed:
            return
        self._installed = False
        self._uninstall()

    def _uninstall(self):
        """
        Module subclasses should implement this method.

        :return: was the module properly uninstalled
        :rtype: bool
        """
        raise NotImplementedError("_uninstall() not implemented")
