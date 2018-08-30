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
import logging
import os

from ..shared.server import Server
from .misc import local_resource


def start_logging():
    """
    Set up the main logger to write to a log file with a specific format and
    intercept both standard output and standard error output.

    :return: the main logger
    """
    Server.add_trace_level()
    logger = logging.getLogger("IDArling")
    logger.setLevel(logging.INFO)

    # Get the absolute path to the log file
    logPath = local_resource("logs", "idarling.%s.log" % os.getpid())

    # Log to the console
    streamHandler = logging.StreamHandler()
    logFormat = "[%(levelname)s] %(message)s"
    formatter = logging.Formatter(fmt=logFormat)
    streamHandler.setFormatter(formatter)
    logger.addHandler(streamHandler)

    # Log to the log file
    fileHandler = logging.FileHandler(logPath)
    logFormat = "[%(asctime)s][%(levelname)s] %(message)s"
    formatter = logging.Formatter(fmt=logFormat, datefmt="%H:%M:%S")
    fileHandler.setFormatter(formatter)
    logger.addHandler(fileHandler)

    return logger
