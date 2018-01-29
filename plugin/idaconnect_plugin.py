from idaconnect.plugin import IDAConnect


def PLUGIN_ENTRY():
    # type: () -> IDAConnect
    """
    Entry point for IDAPython plugins.

    :return: the plugin instance
    """
    return IDAConnect()
