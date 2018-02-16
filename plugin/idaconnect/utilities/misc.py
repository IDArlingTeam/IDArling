import os

import idaapi

LOCAL_PATH = os.path.join(idaapi.get_user_idadir(), '.idaconnect')


def localResource(dirname, filename):
    """
    Get the absolute path of a local resource.

    :param dirname: the directory name
    :param filename: the file name
    :return: the path
    """
    resDir = os.path.join(LOCAL_PATH, dirname)
    if not os.path.exists(resDir):
        os.makedirs(resDir)
    return os.path.join(resDir, filename)


PLUGIN_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


def pluginResource(filename):
    """
    Get the absolute path of a plugin resource.

    :param filename: the fil ename
    :return: the path
    """
    return os.path.join(PLUGIN_PATH, 'resources', filename)


def refreshPseudocodeView():
    """
    Refresh the pseudocode view in IDA
    """
    names = ['Pseudocode-%c' % chr(ord('A') + i) for i in xrange(5)]
    for name in names:
        widget = idaapi.find_widget(name)
        if widget:
            vu = idaapi.get_widget_vdui(widget)
            vu.refresh_view(True)
