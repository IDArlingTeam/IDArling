import os
import sys
import logging

import idaapi


def log(message):
    prefix_message = "[IDAConnect] %s" % message

    if idaapi.is_msg_inited():
        print prefix_message
    else:
        logger.info(message)


def getLogDir():
    return os.path.join(idaapi.get_user_idadir(), '.idaconnect', 'logs')


def loggingStarted():
    return 'logger' in globals()


class LoggerProxy(object):
    def __init__(self, logger, stream, logLevel=logging.INFO):
        self._logger = logger
        self._logLevel = logLevel
        self._stream = stream

    def write(self, buf):
        for line in buf.rstrip().splitlines():
            self._logger.log(self._logLevel, line.rstrip())
        self._stream.write(buf)

    def flush(self):
        pass

    def isatty(self):
        pass


def startLogging():
    global logger
    logger = logging.getLogger('IDAConnect')

    logDir = getLogDir()
    if not os.path.exists(logDir):
        os.makedirs(logDir)
    logPath = os.path.join(logDir, 'idaconnect.%s.log' % os.getpid())

    logging.basicConfig(
        filename=logPath,
        format='%(asctime)s | %(name)20s | %(levelname)7s: %(message)s',
        datefmt='%m-%d-%Y %H:%M:%S',
        level=logging.DEBUG
    )

    stdoutLogger = logging.getLogger('IDAConnect.STDOUT')
    sys.stdout = LoggerProxy(stdoutLogger, sys.stdout, logging.INFO)

    stderrLogger = logging.getLogger('IDAConnect.STDERR')
    sys.stderr = LoggerProxy(stderrLogger, sys.stderr, logging.ERROR)

    return logger
