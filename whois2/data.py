# -*- coding: utf-8 -*-
import os
import re
import yaml

from .utils import data_path

def get_data():
    with open(os.path.join(data_path, 'whois_domain.yaml'), 'r') as f:
        return yaml.load(f.read())
data = get_data()

def get_supported_zone_list():
    return data['zone']

def get_ru_subdomain_zone():
    return [zone for zone in data['zone'] if re.match(r'^(\w+\.(ru$|su$)|ru.net$)', zone)]
