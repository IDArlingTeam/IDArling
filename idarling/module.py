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
    The plugin is organized into modules. Modules allow grouping the
    functionality of the plugin and facilitate information communication.
    """

    def __init__(self, plugin):
        self._plugin = plugin
        self._installed = False

    def install(self):
        """Install the module. Called by the plugin."""
        if self._installed:
            return False
        self._installed = True
        return self._install()

    def _install(self):
        """Install the module. Overloaded by the module."""
        raise NotImplementedError("_install() not implemented")

    def uninstall(self):
        """Uninstall the module. Called by the plugin."""
        if not self._installed:
            return False
        self._installed = False
        return self._uninstall()

    def _uninstall(self):
        """Uninstall the module. Overloaded by the module."""
        raise NotImplementedError("_uninstall() not implemented")
