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

_loggers = {}


def start_logging(log_path, log_name, level):
    """
    Setup the logger: add a new log level, create a logger which logs into
    the console and also into a log files located at: logs/idarling.%pid%.log.
    """
    if log_name in _loggers:
        return _loggers[log_name]

    # Add a new log level called TRACE, and more verbose that DEBUG.
    logging.TRACE = 5
    logging.addLevelName(logging.TRACE, "TRACE")
    logging.Logger.trace = lambda inst, msg, *args, **kwargs: inst.log(
        logging.TRACE, msg, *args, **kwargs
    )
    logging.trace = lambda msg, *args, **kwargs: logging.log(
        logging.TRACE, msg, *args, **kwargs
    )

    logger = logging.getLogger(log_name)
    if not isinstance(level, int):
        level = getattr(logging, level)
    logger.setLevel(level)

    # Log to the console with a first format
    stream_handler = logging.StreamHandler()
    log_format = "[%(levelname)s] %(message)s"
    formatter = logging.Formatter(fmt=log_format)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    # Log to the disk with a second format

    file_handler = logging.FileHandler(log_path)
    log_format = "[%(asctime)s][%(levelname)s] %(message)s"
    formatter = logging.Formatter(fmt=log_format, datefmt="%H:%M:%S")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # Log to the disk too
    file_handler = logging.FileHandler(log_path)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    _loggers[log_name] = logger
    return logger
