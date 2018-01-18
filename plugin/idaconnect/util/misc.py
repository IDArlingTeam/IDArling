import os

PLUGIN_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


def plugin_resource(resource_name):
    return os.path.join(
        PLUGIN_PATH,
        'ui',
        'resources',
        resource_name
    )
