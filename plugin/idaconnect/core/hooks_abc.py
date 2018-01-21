import json

# -----------------------------------------------------------------------------
# Hooks
# -----------------------------------------------------------------------------


class Hooks(object):

    def __init__(self, plugin):
        self._network = plugin.getNetwork()

    def _sendEvent(self, event):
        # Forward packet to network
        self._network.sendPacket(event)
