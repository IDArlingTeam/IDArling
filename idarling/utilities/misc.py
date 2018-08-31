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

import ida_diskio

LOCAL_PATH = os.path.join(ida_diskio.get_user_idadir(), "idarling")


def local_resource(dirname, filename):
    """
    Get the absolute path of a local resource.

    :param dirname: the directory name
    :param filename: the file name
    :return: the path of the resource
    """
    res_dir = os.path.join(LOCAL_PATH, dirname)
    if not os.path.exists(res_dir):
        os.makedirs(res_dir)
    return os.path.join(res_dir, filename)


PLUGIN_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def plugin_resource(filename):
    """
    Get the absolute path of a plugin resource.

    :param filename: the filename
    :return: the path of the resource
    """
    return os.path.join(PLUGIN_PATH, "resources", filename)
