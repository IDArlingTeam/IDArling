import logging
import os
import sys

import idaapi  # type: ignore


class LoggerProxy(object):
    """
    A proxy class used to redirect a standard stream to a logger.
    """

    def __init__(self, stream, logger, level=logging.INFO):
        # type: (file, logging.Logger, int) -> None
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
        # type: (str) -> int
        """
        Called when a string is being written.

        :param buf: the string
        """
        for line in buf.rstrip().splitlines():
            self._logger.log(self._level, line.rstrip())
        return self._stream.write(buf)

    def flush(self):
        # type: () -> None
        """
        Called to flush the internal buffer.
        """
        pass

    def isatty(self):
        # type: () -> bool
        """
        Called to check if this is a tty.
        """
        pass


def startLogging():
    # type: () -> logging.Logger
    """
    Set up the main logger to write to a log file with a specific format and
    intercept both standard output and standard error output.

    :return: the main logger
    """
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
    sys.stdout = LoggerProxy(sys.stdout,  # type: ignore
                             stdoutLogger, logging.INFO)

    # Redirect standard error output to logger
    stderrLogger = logging.getLogger('IDAConnect.STDERR')
    sys.stderr = LoggerProxy(sys.stderr,  # type: ignore
                             stderrLogger, logging.ERROR)

    return logger
