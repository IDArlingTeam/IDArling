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
import os

import idaapi

LOCAL_PATH = os.path.join(idaapi.get_user_idadir(), '.idaconnect')


def localResource(dirname, filename):
    """
    Get the absolute path of a local resource.

    :param dirname: the directory name
    :param filename: the file name
    :return: the path
    """
    resDir = os.path.join(LOCAL_PATH, dirname)
    if not os.path.exists(resDir):
        os.makedirs(resDir)
    return os.path.join(resDir, filename)


PLUGIN_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


def pluginResource(filename):
    """
    Get the absolute path of a plugin resource.

    :param filename: the fil ename
    :return: the path
    """
    return os.path.join(PLUGIN_PATH, 'resources', filename)


def refreshPseudocodeView():
    """
    Refresh the pseudocode view in IDA
    """
    names = ['Pseudocode-%c' % chr(ord('A') + i) for i in xrange(5)]
    for name in names:
        widget = idaapi.find_widget(name)
        if widget:
            vu = idaapi.get_widget_vdui(widget)
            vu.refresh_view(True)
