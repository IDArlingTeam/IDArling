import os

PLUGIN_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def pluginResource(filename):
    """
    Get the absolute path to a resource.

    :param str filename: the filename of the resource
    :rtype: str
    """
    return os.path.join(PLUGIN_PATH, "resources", filename)
