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


def get_log_dir():
    return os.path.join(idaapi.get_user_idadir(), '.idaconnect')


def logging_started():
    return 'logger' in globals()


class LoggerProxy(object):
    def __init__(self, logger, stream, log_level=logging.INFO):
        self._logger = logger
        self._log_level = log_level
        self._stream = stream

    def write(self, buf):
        for line in buf.rstrip().splitlines():
            self._logger.log(self._log_level, line.rstrip())
        self._stream.write(buf)

    def flush(self):
        pass

    def isatty(self):
        pass


def start_logging():
    global logger
    logger = logging.getLogger('IDAConnect')

    log_dir = get_log_dir()
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    log_path = os.path.join(log_dir, 'idaconnect.%s.log' % os.getpid())

    logging.basicConfig(
        filename=log_path,
        format='%(asctime)s | %(name)20s | %(levelname)7s: %(message)s',
        datefmt='%m-%d-%Y %H:%M:%S',
        level=logging.DEBUG
    )

    stdout_logger = logging.getLogger('IDAConnect.STDOUT')
    stderr_logger = logging.getLogger('IDAConnect.STDERR')
    sys.stdout = LoggerProxy(stdout_logger, sys.stdout, logging.INFO)
    sys.stderr = LoggerProxy(stderr_logger, sys.stderr, logging.ERROR)

    return logger
