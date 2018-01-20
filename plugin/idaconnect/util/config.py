import os
import json

import idaapi


def get_config_path():
    config_dir = os.path.join(idaapi.get_user_idadir(), '.idaconnect')
    if not os.path.exists(config_dir):
        os.makedirs(config_dir)
    return os.path.join(log_dir, 'config.json')


def load_config():
    config_path = get_config_path()
    if not os.path.isfile(config_path):
        return {}
    return json.loads(open(config_path))


def save_config(config):
    config_path = get_config_path()
    with open(config_path, 'w') as config_file:
        config_file.write(json.dumps(config, sort_keys=True,
                                     indent=4, separators=(',', ': ')))
