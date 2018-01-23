import os

# -----------------------------------------------------------------------------
# Miscellaneous
# -----------------------------------------------------------------------------


PLUGIN_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def pluginResource(resource):
    return os.path.join(PLUGIN_PATH, "resources", resource)
