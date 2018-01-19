import os

PLUGIN_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


def plugin_resource(resource_name):
    return os.path.join(
        PLUGIN_PATH,
        'ui',
        'resources',
        resource_name
    )


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
