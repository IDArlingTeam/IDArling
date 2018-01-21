import json

# -----------------------------------------------------------------------------
# Hooks
# -----------------------------------------------------------------------------


class Hooks(object):

    def __init__(self, plugin):
        self._network = plugin.getNetwork()

    def _sendEvent(self, event):
        # Serialize the event
        pkt = json.dumps(event)
        self._network.sendPacket(pkt)
