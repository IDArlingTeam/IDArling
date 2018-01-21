# -----------------------------------------------------------------------------
# Packets
# -----------------------------------------------------------------------------


class Packet(dict):

    def __init__(self, type):
        super(Packet, self).__init__()
        self['type'] = type


class CtrlPacket(dict):
    _type = None

    def __init__(self):
        super(CtrlPacket, self).__init__('ctrl')
        self['ctrl_type'] = self._type
