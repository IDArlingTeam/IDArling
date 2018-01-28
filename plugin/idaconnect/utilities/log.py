import logging
import os
import sys

import idaapi


class LoggerProxy(object):
    """
    A proxy class used to redirect a standard stream to a logger.
    """

    def __init__(self, logger_, stream, logLevel=logging.INFO):
        """
        Initialize the proxy class.

        :param logging.Logger logger_: the output logger
        :param file stream: the stream to redirect
        :param int logLevel: the log level to use
        """
        self._logger = logger_
        self._logLevel = logLevel
        self._stream = stream

    def write(self, buf):
        """
        Called when a string is being written.

        :param string buf: the string written
        """
        for line in buf.rstrip().splitlines():
            self._logger.log(self._logLevel, line.rstrip())
        self._stream.write(buf)

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


def loggingStarted():
    """
    Has the main logger already been set up.

    :rtype: bool
    """
    return 'logger' in globals()


def startLogging():
    """
    Set up the main logger to write to a log file with a specific format and
    intercept both standard output and standard error output.

    :return: the main logger
    :rtype: logging.Logger
    """
    global logger
    logger = logging.getLogger('IDAConnect.Plugin')

    # Get the absolute path to the log file
    logDir = os.path.join(idaapi.get_user_idadir(), '.idaconnect', 'logs')
    if not os.path.exists(logDir):
        os.makedirs(logDir)
    logPath = os.path.join(logDir, 'idaconnect.%s.log' % os.getpid())

    # Configure the logger's destination and format
    logging.basicConfig(
        filename=logPath,
        format='[%(asctime)s][%(levelname)s] %(message)s',
        datefmt='%H:%M:%S',
        level=logging.DEBUG)

    # Redirect standard output to logger
    stdoutLogger = logging.getLogger('IDAConnect.STDOUT')
    sys.stdout = LoggerProxy(stdoutLogger, sys.stdout, logging.INFO)

    # Redirect standard error output to logger
    stderrLogger = logging.getLogger('IDAConnect.STDERR')
    sys.stderr = LoggerProxy(stderrLogger, sys.stderr, logging.ERROR)

    return logger
