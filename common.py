import json
import logging

logger = logging.getLogger('pastehunter')


# Parse the config file in to a dict
def parse_config(testing=False):
    if not testing:
        conf_file = 'settings.json'
    else:
        conf_file = 'testing.json'

    conf = None
    try:
        with open(conf_file, 'r') as read_conf:
            conf = json.load(read_conf)
    except Exception as e:
        logger.error("Unable to parse config file: {0}".format(e))

    return conf
