from idaconnect.plugin import Plugin


def PLUGIN_ENTRY():
    """
    Entry point for IDAPython plugins.

    :return: the plugin instance
    """
    return Plugin()
