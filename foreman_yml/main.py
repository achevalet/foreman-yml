#!/usr/bin/python
# -*- coding: utf8 -*-

import argparse
import getpass
import yaml
import sys
import log
from dump import ForemanDump
from convert import ForemanConvert

def main():
    # Get args from cli
    parser = argparse.ArgumentParser(
        description = 'Dump Foreman objects into YAML format')

    parser.add_argument('-a', '--action',
        required  = True,
        action    = 'store',
        choices   = ['dump', 'dump-files', 'convert'],)

    parser.add_argument('-c', '--config_file',
        required  = False,
        action    = 'store',
        help      = 'Path to YAML config file',
        default   = 'config/config.yml')

    parser.add_argument('-f', '--foreman_url',
        required  = False,
        action    = 'store',
        help      = 'Foreman server URL')

    parser.add_argument('-u', '--foreman_user',
        required  = False,
        action    = 'store',
        help      = 'Foreman username')

    parser.add_argument('-p', '--foreman_password',
        required  = False,
        action    = 'store',
        help      = 'Foreman password')

    parser.add_argument('-l', '--log_level',
        required  = False,
        action    = 'store',
        choices   = ['debug', 'info', 'warn', 'error'])

    parser.add_argument('-t', '--type',
        required  = False,
        action    = 'store',
        help      = 'Filter by object type')

    parser.add_argument('-s', '--search',
        required  = False,
        action    = 'store',
        help      = 'Filter by search query, Only valid for: dump, dump-files')

    parser.add_argument('-i', '--input_dir',
        required  = False,
        action    = 'store',
        help      = 'Input folder. Only valid for: convert')

    parser.add_argument('-o', '--output_dir',
        required  = False,
        action    = 'store',
        help      = 'Output folder. Only valid for: dump-files, convert')

    args = parser.parse_args()
    action = args.action

    # load config file
    if args.config_file:
        try:
            config_file = open(args.config_file, 'r')
            config = yaml.load(config_file, Loader=yaml.FullLoader)
            config_file.close()
        except:
            log.log(log.LOG_ERROR, "Failed to load/parse config file")
            sys.exit(1)

    # override config with cli args
    if args.log_level:
        config['log_level'] = args.log_level
    elif not 'log_level' in config:
        # set default level
        config['log_level'] = 'INFO'
    if args.foreman_url:
        config['foreman_url'] = args.foreman_url
    if args.foreman_user:
        config['foreman_user'] = args.foreman_user
    if args.foreman_password:
        config['foreman_password'] = args.foreman_password

    # check required parameters for dump
    if action == 'dump' or action == 'dump-files':
        if not 'foreman_url' in config:
            log.log(log.LOG_ERROR, "Missing parameter foreman_url")
            sys.exit(1)
        if not 'foreman_user' in config:
            log.log(log.LOG_ERROR, "Missing parameter foreman_user")
            sys.exit(1)
        if not 'foreman_password' in config:
            config['foreman_password'] = getpass.getpass(prompt='Enter password for %s: ' %config['foreman_user'])

    # check required parameters for convert
    if action == 'convert' and not args.input_dir:
        log.log(log.LOG_ERROR, "Missing parameter input_dir")
        sys.exit(1)

    # check output folder
    if (action == 'convert' or action == 'dump-files') and not args.output_dir:
        log.log(log.LOG_ERROR, "Missing parameter output_dir")
        sys.exit(1)
 
    # run dump
    if (action == "dump" or action == "dump-files" ):
        fm = ForemanDump(config)
        fm.connect()

        generate_files = False
        if (action == "dump-files"):
            generate_files = True

        fm.dump(args.type, args.search, generate_files, args.output_dir)

    # run convert
    elif (action == "convert" ):
        fm = ForemanConvert(config)
        fm.convert(args.input_dir, args.output_dir, args.type)

if __name__ == '__main__':
    main()
