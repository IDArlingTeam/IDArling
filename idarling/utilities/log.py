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

from .misc import local_resource
from ..shared.server import Server


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
    log_path = local_resource("logs", "idarling.%s.log" % os.getpid())

    # Log to the console
    stream_handler = logging.StreamHandler()
    log_format = "[%(levelname)s] %(message)s"
    formatter = logging.Formatter(fmt=log_format)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    # Log to the log file
    file_handler = logging.FileHandler(log_path)
    log_format = "[%(asctime)s][%(levelname)s] %(message)s"
    formatter = logging.Formatter(fmt=log_format, datefmt="%H:%M:%S")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger
