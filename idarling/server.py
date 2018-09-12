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
import argparse
import os
import signal
import sys
import traceback

from PyQt5.QtCore import QCoreApplication, QTimer

from .shared.server import Server
from .shared.utils import start_logging


class DedicatedServer(Server):
    """
    This is the dedicated server. It can be invoked from the command line. It
    requires only PyQt5 and should be invoked from Python 3. The dedicated
    server should be used when the integrated doesn't fulfil the user's needs.
    """

    def __init__(self, level, parent=None):
        # Get the path to the log file
        log_dir = os.path.join(os.path.dirname(__file__), "logs")
        log_dir = os.path.abspath(log_dir)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        log_path = os.path.join(log_dir, "idarling.%s.log" % os.getpid())

        logger = start_logging(log_path, "IDArling.Server", level)
        Server.__init__(self, logger, parent)

    def server_file(self, filename):
        """
        This function returns the absolute path to a server's file. It should
        be located within a files/ subdirectory of the current directory.
        """
        files_dir = os.path.join(os.path.dirname(__file__), "files")
        files_dir = os.path.abspath(files_dir)
        if not os.path.exists(files_dir):
            os.makedirs(files_dir)
        return os.path.join(files_dir, filename)


def start(args):
    app = QCoreApplication(sys.argv)
    sys.excepthook = traceback.print_exception

    server = DedicatedServer(args.level)
    server.SNAPSHOT_INTERVAL = args.interval
    server.start(args.host, args.port, args.ssl)

    # Allow the use of Ctrl-C to stop the server
    def sigint_handler(_, __):
        server.stop()
        app.exit(0)

    signal.signal(signal.SIGINT, sigint_handler)

    # This timer gives the application a chance to be interrupted every 50 ms
    # even if it stuck in a loop or something
    def safe_timer(timeout, func, *args, **kwargs):
        def timer_event():
            try:
                func(*args, **kwargs)
            finally:
                QTimer.singleShot(timeout, timer_event)

        QTimer.singleShot(timeout, timer_event)

    safe_timer(50, lambda: None)

    return app.exec_()


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        "--help", action="help", help="show this help message and exit"
    )

    # Users can specify the host and port to start the server on
    parser.add_argument(
        "-h",
        "--host",
        type=str,
        default="127.0.0.1",
        help="the hostname to start listening on",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=31013,
        help="the port to start listening on",
    )

    # Users must specify the path to the certificate chain and the
    # corresponding private key of the server, or disable SSL altogether.
    security = parser.add_mutually_exclusive_group(required=True)
    security.add_argument(
        "--ssl",
        type=str,
        nargs=2,
        metavar=("fullchain.pem", "privkey.pem"),
        help="the certificate and private key files",
    )
    security.add_argument(
        "--no-ssl", action="store_true", help="disable SSL (not recommended)"
    )

    # Users can also change the logging level if the they want some debug
    levels = ["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "TRACE"]
    parser.add_argument(
        "-l",
        "--level",
        type=str,
        choices=levels,
        default="INFO",
        help="the log level",
    )

    # Interval in ticks between database snapshot
    parser.add_argument(
        "-i",
        "--interval",
        type=int,
        default=0,
        help="database snapshot interval",
    )

    start(parser.parse_args())
