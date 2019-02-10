import configparser
import os


class settings:
    ip = ''
    port = ''
    folder = ''
    webfolder = ''

# Settings
def readconf():
    config = configparser.ConfigParser()
    working_dir = os.getcwd()
    configuration_file = 'puckoo.conf'
    config.read((os.path.join(working_dir, configuration_file)))
    # cuckoo
    puckoo_conf = config['puckoo']
    settings.port = puckoo_conf.get('port')
    settings.ip = puckoo_conf.get('ip')
    settings.folder = puckoo_conf.get('base_folder')
    settings.webfolder = puckoo_conf.get('web_folder')
    
