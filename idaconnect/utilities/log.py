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
import sys

from .misc import local_resource


class LoggerProxy(object):
    """
    A proxy class used to redirect a standard stream to a logger.
    """

    def __init__(self, stream, logger, level=logging.INFO):
        """
        Initialize the proxy class.

        :param stream: the stream to redirect
        :param logger: the logger to use
        :param level: the log level to use
        """
        self._stream = stream
        self._logger = logger
        self._level = level

    def write(self, buf):
        """
        Called when a string is being written.

        :param buf: the string
        """
        for line in buf.rstrip().splitlines():
            self._logger.log(self._level, line.rstrip())
        return self._stream.write(buf)

    def flush(self):
        """
        Called to flush the internal buffer.
        """
        pass

    def isatty(self):
        """
        Called to check if this is a tty.
        """
        pass


def start_logging():
    """
    Set up the main logger to write to a log file with a specific format and
    intercept both standard output and standard error output.

    :return: the main logger
    """
    logger = logging.getLogger('IDAConnect')

    # Get the absolute path to the log file
    logPath = local_resource('logs', 'idaconnect.%s.log' % os.getpid())

    # Configure the logger
    logger.setLevel(logging.DEBUG)
    logFormat = '[%(asctime)s][%(levelname)s] %(message)s'
    formatter = logging.Formatter(fmt=logFormat, datefmt='%H:%M:%S')

    # Log to the console
    streamHandler = logging.StreamHandler()
    streamHandler.setFormatter(formatter)
    logger.addHandler(streamHandler)

    # Log to the log file
    fileHandler = logging.FileHandler(logPath)
    fileHandler.setFormatter(formatter)
    logger.addHandler(fileHandler)

    return logger
