import os

PLUGIN_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


def pluginResource(resourceName):
    return os.path.join(
        PLUGIN_PATH,
        'ui',
        'resources',
        resourceName
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


def makeMetaClass(registry):
    class MetaRegistry(type):

        def __new__(cls, name, bases, attrs):
            newCls = type.__new__(cls, name, bases, attrs)
            registry[newCls._type] = newCls
            return newCls
    return MetaRegistry
