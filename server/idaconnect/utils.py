# Copyright (C) 2018 Alexandre Adamski
# Copyright (C) 2018 Joffrey Guilbon
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of  MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program.  If not, see <http://www.gnu.org/licenses/>.
import logging
import os

from twisted.python import log


def localFile(filename):
    """
    Get the absolute path of a local file.

    :param filename: the file name
    :return: the path
    """
    parDir = os.path.join(os.path.dirname(__file__), os.pardir)
    filesDir = os.path.abspath(os.path.join(parDir, 'files'))
    if not os.path.exists(filesDir):
        os.makedirs(filesDir)
    return os.path.join(filesDir, filename)


def startLogging():
    """
    Set up the main logger to write both to a log file and to the console
    using a specific format, and bind Twisted to the Python logger.

    :return: the main logger
    """
    LOGGER_NAME = 'IDAConnect.Server'

    # Bind Twisted to Python log
    observer = log.PythonLoggingObserver(loggerName=LOGGER_NAME)
    observer.start()

    global logger
    logger = logging.getLogger(LOGGER_NAME)

    # Get path to the log file
    parDir = os.path.join(os.path.dirname(__file__), os.pardir)
    logDir = os.path.abspath(os.path.join(parDir, 'logs'))
    if not os.path.exists(logDir):
        os.makedirs(logDir)
    logPath = os.path.join(logDir, 'idaconnect.%s.log' % os.getpid())

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
