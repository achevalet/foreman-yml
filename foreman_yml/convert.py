#!/usr/bin/python
# -*- coding: utf8 -*-


import sys
import os
import logging
import log
import yaml
from base import ForemanBase


class ForemanConvert(ForemanBase):

    # convert functionality
    def convert(self, input_dir, output_dir, filter_object=None):
        # debug params
        log.log(log.LOG_DEBUG, "input_dir: " + input_dir)
        log.log(log.LOG_DEBUG, "output_dir: " + output_dir)
        if filter_object:
            log.log(log.LOG_DEBUG, "filter_object: " + filter_object)

        # define supported objects
        supported_objects = self.get_all_objects()
        excluded_objects = ['hosts-enc']
        for obj in excluded_objects:
            supported_objects.remove(obj)

        # check input folder
        if not os.path.exists(input_dir):
            log.log(log.LOG_ERROR, "input folder %s does not exist" %input_dir)
            sys.exit(1)
        if input_dir == output_dir:
            log.log(log.LOG_ERROR, "input and output folder must be different")
            sys.exit(1)

        # create output folder
        log.log(log.LOG_DEBUG, "creating output folder %s" %output_dir)
        self.ensure_dir(output_dir)

        # loop on all subfolders (object types)
        for object_type in os.listdir(input_dir):

            # check supported objects
            if object_type not in supported_objects:
                log.log(log.LOG_DEBUG, "skipping '%s' (unknown object type)" %object_type)
                continue
            if filter_object and filter_object != object_type:
                log.log(log.LOG_DEBUG, "skipping '%s'" %object_type)
                continue

            log.log(log.LOG_INFO, "converting '%s'" %object_type)

            # create output object folder 
            output_dir_objects = output_dir.strip('/') + '/' + object_type
            log.log(log.LOG_DEBUG, "creating output folder %s" %output_dir_objects)
            self.ensure_dir(output_dir_objects)

            # loop on all .yml files in subfolder
            input_dir_objects = input_dir.strip('/') + '/' + object_type
            for file in os.listdir(input_dir_objects):
                if not file.endswith('.yml'):
                    log.log(log.LOG_DEBUG, "skipping file '%s/%s' (unknown extension)" %(object_type, file))
                    continue
                log.log(log.LOG_DEBUG, "converting %s '%s'" %(object_type, file))

                # load input file
                in_path = "%s/%s" %(input_dir_objects, file)
                log.log(log.LOG_DEBUG, "reading input file %s" %in_path)
                data = self.read_yml_file(in_path)
                log.log(log.LOG_DEBUG, "input data: %s" %data)

                # convert data
                convert_func = getattr(self, 'convert_%s' %object_type.replace('-', '_'))
                ansible_data = convert_func(data)
                log.log(log.LOG_DEBUG, "output data: %s" %ansible_data)

                # write output file
                out_path = "%s/%s" %(output_dir_objects, file)
                log.log(log.LOG_DEBUG, "writing output file %s" %out_path)
                yml_data = yaml.dump(ansible_data, allow_unicode=True, default_flow_style=False)
                self.write_yml_file(out_path, yml_data)


    def convert_activation_keys(self, data):
        return {}


    def convert_architecture(self, data):
        return {}


    def convert_auth_source_ldap(self, data):
        return {}


    def convert_bookmark(self, data):
        return {}


    def convert_compute_profile(self, data):
        return {}


    def convert_compute_resource(self, data):
        return {}


    def convert_content_views(self, data):
        return {}


    def convert_domain(self, data):
        return {}


    def convert_environment(self, data):
        return {}


    def convert_global_parameter(self, data):
        return {}


    def convert_gpg_keys(self, data):
        return {}


    def convert_hostgroup(self, data):
        return {}


    def convert_hosts(self, data):
        return {}


    def convert_job_template(self, data):
        return {}


    def convert_lifecycle_environments(self, data):
        return {}


    def convert_location(self, data):
        return {}


    def convert_media(self, data):
        return {}


    def convert_model(self, data):
        return {}


    def convert_organization(self, data):
        return {}


    def convert_os(self, data):
        return {}


    def convert_partition_table(self, data):
        return {}


    def convert_products(self, data):
        return {}


    def convert_provisioning_template(self, data):
        return {}


    def convert_repos(self, data):
        return {}


    def convert_roles(self, data):
        return {}


    def convert_settings(self, data):
        return {}


    def convert_smart_class_parameter(self, data):
        return {}


    def convert_smart_proxy(self, data):
        return {}


    def convert_subnet(self, data):
        return {}


    def convert_sync_plans(self, data):
        return {}


    def convert_usergroups(self, data):
        return {}


    def convert_users(self, data):
        return {}
