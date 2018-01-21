import os

# -----------------------------------------------------------------------------
# Miscellaneous Utilities
# -----------------------------------------------------------------------------


PLUGIN_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def pluginResource(resource):
    return os.path.join(PLUGIN_PATH, "resources", resource)


def byteify(input):
    if isinstance(input, dict):
        return {byteify(key): byteify(value)
                for key, value in input.iteritems()}
    elif isinstance(input, list):
        return [byteify(element) for element in input]
    elif isinstance(input, unicode):
        return input.encode('utf-8')
    else:
        return input
