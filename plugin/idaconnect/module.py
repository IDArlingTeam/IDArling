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


class Module(object):
    """
    This is the base class of every module in the plugin.
    """

    def __init__(self, plugin):
        """
        Initialize the module.

        :param plugin: the plugin instance
        """
        self._plugin = plugin
        self._installed = False

    def install(self):
        """
         Install the module (called by the plugin).

         :return: if the module was properly installed
        """
        if self._installed:
            return False
        self._installed = True
        return self._install()

    def _install(self):
        """
        Install the module (called by the base class).

        :return: if the module was properly installed
        """
        raise NotImplementedError("_install() not implemented")

    def uninstall(self):
        """
        Uninstall the module (called by the plugin).

        :return: if the module was properly uninstalled
        """
        if not self._installed:
            return False
        self._installed = False
        return self._uninstall()

    def _uninstall(self):
        """
        Uninstall the module (called by the base class).

        :return: if the module properly uninstalled
        """
        raise NotImplementedError("_uninstall() not implemented")
