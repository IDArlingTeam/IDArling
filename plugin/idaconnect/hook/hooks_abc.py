import logging

import logging


class Hooks(object):

    def __init__(self, network):
        self._network = network

    def _sendEvent(self, event):
        self._network.sendEvent(event)
