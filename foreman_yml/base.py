import os
import sys
import logging
import log
import urllib3
import yaml
from foreman.client import Foreman

FOREMAN_OBJECTS = [
    'architecture',
    'auth-source-ldap',
    'bookmark',
    'compute-resource',
    'compute-profile',
    'domain',
    'environment',
    'global-parameter',
    'hosts',
    'hosts-enc',
    'hostgroup',
    'job-template',
    'location',
    'model',
    'media',
    'organization',
    'os',
    'partition-table',
    'provisioning-template',
    'roles',
    'settings',
    'smart-class-parameter',
    'smart-proxy',
    'subnet',
    'users',
    'usergroups'
]
KATELLO_OBJECTS = [
    'activation-keys',
    'content-views',
    'gpg-keys',
    'lifecycle-environments',
    'products',
    'repos',
    'sync-plans'
]

class ForemanBase:

    def __init__(self, config):
        self.config = config
        self.loglevel = getattr(logging, config['log_level'].upper(), None)
        logging.basicConfig(level=self.loglevel)
        log.LOGLEVEL = self.loglevel

    def connect(self): 
        try:
            urllib3.disable_warnings()
            logging.disable(logging.WARNING)
            self.fm = Foreman(self.config['foreman_url'], (self.config['foreman_user'], self.config['foreman_password']),
                api_version=2, use_cache=False, strict_cache=False, timeout=900)
            # check api access
            self.fm.status.home_status()
            logging.disable(self.loglevel-1)
        except:
            log.log(log.LOG_ERROR, "Cannot connect to Foreman-API")
            sys.exit(1)

    def get_all_objects(self):
        objects = FOREMAN_OBJECTS + KATELLO_OBJECTS
        objects.sort()
        return objects

    def get_supported_objects(self):
        try:
            # check katello status
            katello_status = self.fm.status.ping_server_status()
            return self.get_all_objects()
        except:
            FOREMAN_OBJECTS.sort()
            return FOREMAN_OBJECTS

    def dict_underscore(self, d):
        new = {}
        for k, v in d.iteritems():
            if isinstance(v, dict):
                v = self.dict_underscore(v)
            new[k.replace('-', '_')] = v
        return new

    def dict_dash(self, d):
        new = {}
        for k, v in d.iteritems():
            if isinstance(v, dict):
                v = self.dict_dash(v)
            new[k.replace('_', '-')] = v
        return new

    def filter_dump(self, dump, wanted_keys):
        ret = {}
        dd = self.dict_dash(dump)
        for setting in dd:
            if setting in wanted_keys:
                value = dd[setting]
                if value is None or value=='' or value==[] or value=={}:
                    continue
                ret[setting] = value
        return ret

    def rstrip_multilines(self, data):
        out = []
        for line in data.splitlines():
            out.append(line.rstrip())
        return '\n'.join(out)

    def ensure_dir(self, directory):
        if not os.path.exists(directory):
            os.makedirs(directory)

    def write_yml_file(self, file, data):
        f = open(file, 'w')
        f.write(data)
        f.close

    def read_yml_file(self, file):
        data = {}
        with open(file, 'r') as input_file:
            try:
                data = yaml.safe_load(input_file)
            except yaml.YAMLError as exception:
                raise exception
        return data
