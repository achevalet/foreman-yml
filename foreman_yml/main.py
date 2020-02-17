#!/usr/bin/python
# -*- coding: utf8 -*-

import yaml
import sys
from importer import ForemanImport
from dump import ForemanDump
from cleanup import ForemanCleanup
import os
import log


def fm_dump(fm, object=None, search=None, generate_files=False):
    fm.dump(object, search, generate_files)


def fm_cleanup(fm):
    # cleanup architecture
    fm.process_cleanup_arch()

    # cleanup medium
    fm.process_cleanup_medium()

    # cleanup partition table
    fm.process_cleanup_ptable()

    # cleanup provisioning template
    fm.process_cleanup_provisioningtpl()


def fm_import(fm):
    # setting
    fm.process_config_settings()

    # architecture
    fm.process_config_arch()

    # smart proxy
    fm.process_config_smartproxy()

    # domain
    fm.process_config_domain()

    # subnet
    fm.process_config_subnet()

    # environment
    fm.process_config_enviroment()

    # model
    fm.process_config_model()

    # medium
    fm.process_config_medium()

    # partition table
    fm.process_config_ptable()

    # operating system
    fm.process_config_os()

    # provisioning template
    fm.process_config_provisioningtpl()

    # hostgroup
    fm.process_config_hostgroup()

    # Link items to operating system
    fm.process_config_os_link()

    # Link template-combination-attribute
    fm.process_template_combination_attribute()

    # host
    fm.process_config_host()

    # enterprise edition only: ldap
    fm.process_auth_sources_ldap()

    # roles
    fm.process_roles()

    # users
    fm.process_config_user()

    # user groups
    fm.process_usergroups()


def main():

    try:
        function = sys.argv[1]
    except:
        log.log(log.LOG_ERROR, "No action defined (Valid: dump, import, cleanup)")
        sys.exit(1)

    if os.path.isfile(sys.argv[1]):
        config_file = sys.argv[1]
        function = "legacy"
    else:
        try:
            config_file = sys.argv[2]
        except IndexError:
            log.log(log.LOG_ERROR, "No YAML provided")
            sys.exit(1)

    try:
        config_file = open(config_file, 'r')
        config = yaml.load(config_file, Loader=yaml.FullLoader)
        config_file.close()
    except:
        log.log(log.LOG_ERROR, "Failed to load/parse config")
        sys.exit(1)

    if (function == "import"):
        fm = ForemanImport(config)
        fm.connect()
        fm_import(fm)

    if (function == "dump" or function == "dump-files" ):
        generate_files = False
        if (function == "dump-files"):
            generate_files = True
        fm = ForemanDump(config)
        fm.connect()
        try:
            object = sys.argv[3]
        except IndexError:
            object = None
        try:
            search = sys.argv[4]
        except IndexError:
            search = None
        
        fm_dump(fm, object, search, generate_files)

    if (function == "cleanup"):
        fm = ForemanCleanup(config)
        fm.connect()
        fm_cleanup(fm)

    if (function == "legacy"):
        fm_cls = ForemanCleanup(config)
        fm_cls.connect()
        fm_cleanup(fm_cls)
        fm_imp = ForemanImport(config)
        fm_imp.connect()
        fm_import(fm_imp)


if __name__ == '__main__':
    main()
