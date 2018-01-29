import os


PLUGIN_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def pluginResource(filename):
    # type: (str) -> str
    """
    Get the absolute path of a plugin resource.

    :param filename: the filename
    :return: the path
    """
    return os.path.join(PLUGIN_PATH, "resources", filename)
