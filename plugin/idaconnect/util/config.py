import os
import json

import idaapi


def getConfigPath():
    configDir = os.path.join(idaapi.get_user_idadir(), '.idaconnect')
    if not os.path.exists(configDir):
        os.makedirs(configDir)
    return os.path.join(configDir, 'config.json')


def loadConfig():
    configPath = getConfigPath()
    if not os.path.isfile(configPath):
        return {}
    return json.loads(open(configPath))


def saveConfig(config):
    configPath = getConfigPath()
    with open(configPath, 'w') as configFile:
        configFile.write(json.dumps(config, sort_keys=True,
                                    indent=4, separators=(',', ': ')))
