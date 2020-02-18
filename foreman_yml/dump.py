#!/usr/bin/python
# -*- coding: utf8 -*-


import sys
import logging
import log
from base import ForemanBase
import yaml
from collections import OrderedDict
from pprint import pprint
from foreman.client import Foreman, ForemanException


import re
from cStringIO import StringIO

def _fix_dump(dump, indentSize=2):
    stream = StringIO(dump)
    out = StringIO()
    pat = re.compile('(\s*)([^:]*)(:*)')
    last = None

    prefix = 0
    for s in stream:
        indent, key, colon = pat.match(s).groups()
        if indent=="" and key[0]!= '-':
            prefix = 0
        if last:
            if len(last[0])==len(indent) and last[2]==':':
                if all([
                        not last[1].startswith('-'),
                        s.strip().startswith('-')
                        ]):
                    prefix += indentSize
        out.write(" "*prefix+s)
        last = indent, key, colon
    return out.getvalue()



class ForemanDump(ForemanBase):



    # dump functionality
    def dump(self, object=None, search=None, generate_files=False):
        dumpdata = {}
        all_objects = []
        # define supported objects (restrict dump functions name)
        supported_objects = [
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
        supported_katello_objects = [
            'gpg-keys',
            'sync-plans',
            'products',
            'repos',
            'lifecycle-environments',
            'content-views',
            'activation-keys'
        ]
        generate_files_dir = 'foreman_yml_files'

        # check katello status
        try:
            self.katello_status = self.fm.status.ping_server_status()
            supported_objects = supported_objects + supported_katello_objects
        except:
            pass

        supported_objects.sort()

        # define target objects
        if object is not None:
            if object not in supported_objects:
                log.log(log.LOG_ERROR, "Object must be one of %s" %supported_objects)
                sys.exit(1)
            all_objects = [object]
        else:
            all_objects = supported_objects

        # get all organizations
        self.all_org = self.fm.organizations.index(per_page=99999)['results']

        # dump objects
        for object in all_objects:
            dump_func = getattr(self, 'dump_%s' %object.replace('-', '_'))
            dumpdata[object] = dump_func(search)

        # filter empty objects
        dumpdata = self.filter_dump(dumpdata, supported_objects)

        def str_presenter(dumper, data):
            try:
                dlen = len(data.splitlines())
            except TypeError:
                return dumper.represent_scalar('tag:yaml.org,2002:str', data)
            if (dlen > 1):
                return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')

            return dumper.represent_scalar('tag:yaml.org,2002:str', data)

        yaml.add_representer(unicode, str_presenter)
        yaml.add_representer(str, str_presenter)

        if generate_files == False:
            # print the result to stdout
            fmyml = { 'foreman': dumpdata }
            yml = yaml.dump(fmyml, allow_unicode=True, default_flow_style=False )
            print( (yml) )
        else:
            # generate per object yaml files
            self.ensure_dir(generate_files_dir)
            for obj in dumpdata:
                objdir = generate_files_dir + '/' + obj
                self.ensure_dir(objdir)
                for elmt in dumpdata[obj]:
                   yml_file = objdir + '/' + elmt.keys()[0].replace('/', '__') + '.yml'
                   yml_data = yaml.dump(elmt, allow_unicode=True, default_flow_style=False )
                   self.write_yml_file(yml_file, yml_data)


    def dump_hosts(self, search=None):
        ret = []
        all_hosts = self.fm.hosts.index(per_page=99999,search=search)['results']
        for host in all_hosts:
            host_tpl = {}
            if 'name' in host:
                name = host['name']
            else:
                continue
            host_tpl[name] = {}
            for setting in host:
                value = host[setting]
                if value is None or value=='':
                    continue
                if (setting == "name"):
                    host_tpl[name]['name'] = value
                elif (setting == "operatingsystem_name"):
                    host_tpl[name]['os'] = value
                elif (setting == "environment_name"):
                    host_tpl[name]['environment'] = value
                elif (setting == "architecture_name"):
                    host_tpl[name]['architecture'] = value
                elif (setting == "medium_name"):
                    host_tpl[name]['media'] = value
                elif (setting == "domain_name"):
                    host_tpl[name]['domain'] = value
                elif (setting == "ptable_name"):
                    host_tpl[name]['partition'] = value
                elif (setting == "model_name"):
                    host_tpl[name]['model'] = value
                elif (setting == "hostgroup_title"):
                    host_tpl[name]['hostgroup'] = value
                elif (setting == "ip"):
                    host_tpl[name]['ip'] = value
                elif (setting == "mac"):
                    host_tpl[name]['mac'] = value
                elif (setting == "subnet_name"):
                    host_tpl[name]['subnet'] = value
                elif (setting == "owner_name"):
                    host_tpl[name]['owner'] = value
                elif (setting == "owner_type"):
                    host_tpl[name]['owner-type'] = value
                elif (setting == "enabled"):
                    host_tpl[name]['enabled'] = value
                elif (setting == "managed"):
                    host_tpl[name]['enabled'] = value
                elif (setting == "compute_resource_name"):
                    host_tpl[name]['compute-resource'] = value
                elif (setting == "puppet_proxy_name"):
                    host_tpl[name]['puppet-proxy'] = value
                elif (setting == "puppet_ca_proxy_name"):
                    host_tpl[name]['puppet-ca-proxy'] = value
            # host params
            try:
                hobj = self.fm.hosts.show(host['id'],show_hidden_parameters='true')
                if (len(hobj['parameters'])>0):
                    host_tpl[name]['parameters'] = {}
                    for param in hobj['parameters']:
                        host_tpl[name]['parameters'][param['name']] = param['value']
            except:
                pass

            ret.append(host_tpl)
        return ret


    def dump_hosts_enc(self, search=None):
        ret = []
        all_hosts = self.fm.hosts.index(per_page=99999,search=search)['results']
        for host in all_hosts:
            host_tpl = {}
            if not 'name' in host:
                continue
            host_tpl[host['name']] = self.fm.hosts.enc(host['id'])
            ret.append(host_tpl)

        return ret


    def dump_hostgroup(self, search=None):
        ret = []
        all_groups = self.fm.hostgroups.index(per_page=99999,search=search)['results']
        for group in all_groups:
            grp_tpl = {}
            if 'title' in group:
                name = group['title']
            else:
                continue
            grp_tpl[name] = {}
            for setting in group:
                value = group[setting]
                if value is None or value=='':
                    continue
                if (setting == "name"):
                    grp_tpl[name]['name'] = value
                elif (setting == "operatingsystem_name"):
                    grp_tpl[name]['os'] = value
                elif (setting == "environment_name"):
                    grp_tpl[name]['environment'] = value
                elif (setting == "architecture_name"):
                    grp_tpl[name]['architecture'] = value
                elif (setting == "medium_name"):
                    grp_tpl[name]['media'] = value
                elif (setting == "domain_name"):
                    grp_tpl[name]['domain'] = value
                elif (setting == "ptable_name"):
                    grp_tpl[name]['partition'] = value
                elif (setting == "subnet_name" ):
                    grp_tpl[name]['subnet'] = value
                elif (setting == "title" ):
                    grp_tpl[name]['title'] = value
                elif (setting == "parent_name" ):
                    grp_tpl[name]['parent'] = value
            try:
                hobj = self.fm.hostgroups.show(group['id'],show_hidden_parameters='true')
                if (len(hobj['parameters'])>0):
                    grp_tpl[name]['parameters'] = {}
                    for param in hobj['parameters']:
                        grp_tpl[name]['parameters'][param['name']] = param['value']
                if (len(hobj['puppetclasses'])>0):
                    grp_tpl[name]['puppetclasses'] = []
                    for pclass in hobj['puppetclasses']:
                        grp_tpl[name]['puppetclasses'].append(pclass['name'])

            except:
                pass
            ret.append(grp_tpl)
        return ret


    def dump_architecture(self, search=None):
        ret = []
        all_archs = self.fm.architectures.index(per_page=99999,search=search)['results']
        for arch in all_archs:
            tpl = {}
            tpl[arch['name']] = { 'name': arch['name'] }
            ret.append(tpl)
        return ret


    def dump_environment(self, search=None):
        ret = []
        all_envs = self.fm.environments.index(per_page=99999,search=search)['results']
        for env in all_envs:
            tpl = {}
            tpl[env['name']] = { 'name': env['name'] }
            ret.append(tpl)
        return ret


    def dump_os(self, search=None):
        ret = []
        all_os = self.fm.operatingsystems.index(per_page=99999,search=search)['results']
        for os in all_os:
            os_tpl = {}
            if os['description']:
                name = os['description']
            else:
                name = "%s %s" %(os['name'], os['major'])
            os_tpl[name] = {}
            for setting in os:
                value = os[setting]
                if value is None or value=='':
                    continue
                if (setting == "name"):
                    os_tpl[name]['name'] = value
                if (setting == "major"):
                    os_tpl[name]['major'] = str(value)
                if (setting == "minor"):
                    os_tpl[name]['minor'] = str(value)
                if (setting == "description"):
                    os_tpl[name]['description'] = value
                if (setting == "release_name"):
                    os_tpl[name]['release_name'] = value
                if (setting == "family"):
                    os_tpl[name]['family'] = value
                if (setting == "password_hash"):
                    os_tpl[name]['password-hash'] = value
            osobj = self.fm.operatingsystems.show(os['id'])
            # media
            if (len(osobj['media'])>0):
                os_tpl[name]['media'] = []
                for media in osobj['media']:
                    os_tpl[name]['media'].append(media['name'])
            # provisioning templates
            if (len(osobj['os_default_templates'])>0):
                os_tpl[name]['provisioning-template'] = []
                for pt in osobj['os_default_templates']:
                    os_tpl[name]['provisioning-template'].append(pt['provisioning_template_name'])
            # architectures
            if (len(osobj['architectures'])>0):
                os_tpl[name]['architectures'] = []
                for pt in osobj['architectures']:
                    os_tpl[name]['architectures'].append(pt['name'])
            # partition tables
            if (len(osobj['ptables'])>0):
                os_tpl[name]['partition-table'] = []
                for pt in osobj['ptables']:
                    os_tpl[name]['partition-table'].append(pt['name'])
            ret.append(os_tpl)
        return ret


    def dump_media(self, search=None):
        ret = []
        all_media = self.fm.media.index(per_page=99999,search=search)['results']
        mod_tpl = {}
        for medium in all_media:
            med_tpl = {}
            if 'name' in medium:
                name = medium['name']
            else:
                continue
            med_tpl[name] = {}
            for setting in medium:
                value = medium[setting]
                if value is None or value=='':
                    continue
                if (setting == "name"):
                    med_tpl[name]['name'] = value
                if (setting == "path"):
                    med_tpl[name]['path'] = value
                if (setting == "os_family"):
                    med_tpl[name]['os-family'] = value
            ret.append(med_tpl)
        return ret


    def dump_model(self, search=None):
        ret = []
        all_mods = self.fm.models.index(per_page=99999,search=search)['results']
        for model in all_mods:
            mod_tpl = {}
            if 'name' in model:
                name = model['name']
            else:
                continue
            mod_tpl[name] = {}
            for setting in model:
                value = model[setting]
                if value is None or value=='':
                    continue
                if (setting == "name"):
                    mod_tpl[name]['name'] = value
                if (setting == "hardware_model"):
                    mod_tpl[name]['hardware-model'] = value
                if (setting == "vendor_class"):
                    mod_tpl[name]['vendor-class'] = value
                if (setting == "info"):
                    mod_tpl[name]['info'] = value
            ret.append(mod_tpl)
        return ret


    def dump_domain(self, search=None):
        ret = []
        all_doms = self.fm.domains.index(per_page=99999,search=search)['results']
        for dom in all_doms:
            dom_tpl = {}
            if 'name' in dom:
                name = dom['name']
            else:
                continue
            dom_tpl[name] = {}
            for setting in dom:
                value = dom[setting]
                if value is None or value=='':
                    continue
                if (setting == "name"):
                    dom_tpl[name]['name'] = value
                if (setting == "fullname"):
                    dom_tpl[name]['fullname'] = value
                if (setting == "dns"):
                    dom_tpl[name]['dns-proxy'] = value['name']
            # params
            domobj = self.fm.domains.show(dom['id'],show_hidden_parameters='true')
            if (len(domobj['parameters'])>0):
                dom_tpl[name]['parameters'] = {}
                for param in domobj['parameters']:
                    dom_tpl[name]['parameters'][param['name']] = param['value']
            ret.append(dom_tpl)
        return ret


    def dump_smart_proxy(self, search=None):
        ret = []
        wanted_keys = [
            "name",
            "url",
            "download-policy"
        ]
        all_proxys = self.fm.smart_proxies.index(per_page=99999,search=search)['results']
        for proxy in all_proxys:
            sp_tpl = {}
            if 'name' in proxy:
                name = proxy['name']
            else:
                continue
            sp_tpl[name] = self.filter_dump(proxy, wanted_keys)
            ret.append(sp_tpl)
        return ret


    def dump_subnet(self, search=None):
        ret = []
        wanted_keys = [
            "name",
            "network",
            "mask",
            "gateway",
            "ipam",
            "from",
            "to",
            "vlanid",
            "dns-primary",
            "dns-secondary",
            "boot-mode",
            "network-type",
            "dhcp-name",
            "tftp-name",
            "httpboot-name",
            "template-name",
            "mtu"
        ]
        all_subnets = self.fm.subnets.index(per_page=99999,search=search)['results']
        for subnet in all_subnets:
            subnet_tpl = {}
            if 'name' in subnet:
                name = subnet['name']
            else:
                continue

            subnet_tpl[name] = self.filter_dump(subnet, wanted_keys)

            # domains
            subnet_tpl[name]['domain'] = []
            all_doms = self.fm.subnets.domains_index(subnet['id'])
            for dom in all_doms['results']:
                subnet_tpl[name]['domain'].append(dom['name'])

            # params
            sobj = self.fm.subnets.show(subnet['id'],show_hidden_parameters='true')
            if (len(sobj['parameters'])>0):
                subnet_tpl[name]['parameters'] = {}
                for param in sobj['parameters']:
                    subnet_tpl[name]['parameters'][param['name']] = param['value']

            ret.append(subnet_tpl)

        return ret


    def dump_settings(self, search=None):
        ret = []
        wanted_keys = [
            "category-name",
            "description",
            "full-name",
            "name",
            "value"
        ]
        all_settings = self.fm.settings.index(per_page=99999,search=search)['results']
        for settings in all_settings:
            set_tpl = {}
            # skip default settings
            if settings['value'] == settings['default']:
                continue
            set_tpl[settings['name']] = self.filter_dump(settings, wanted_keys)
            ret.append(set_tpl)
        return ret


    def dump_partition_table(self, search=None):
        ret = []
        all_ptables = self.fm.ptables.index(per_page=99999,search=search)['results']
        for ptable in all_ptables:
            pt_tpl = {}
            if 'name' in ptable:
                name = ptable['name']
            else:
                continue
            pt_tpl[name] = {}
            for setting in ptable:
                value = ptable[setting]
                if value is None or value=='':
                    continue
                if (setting == "name"):
                    pt_tpl[name]['name'] = value
                if (setting == "os_family"):
                    pt_tpl[name]['os-family'] = value
            # all other values need to be fetched from obj itself
            ptobj = self.fm.ptables.show(ptable['id'])
            try:
                pt_tpl[name]['locked'] = ptobj['locked']
            except KeyError:
                pass
            try:
                pt_tpl[name]['snippet'] = ptobj['snippet']
            except KeyError:
                pass
            try:
                pt_tpl[name]['layout'] = self.rstrip_multilines(ptobj['layout'])
            except KeyError:
                pass
            ret.append(pt_tpl)

        return ret



    def dump_provisioning_template(self, search=None):
        ret = []
        wanted_keys = [
            "snippet",
            "name",
            "template-kind-id",
            "locked",
            "audit-comment"
        ]
        all_provt = self.fm.provisioning_templates.index(per_page=99999,search=search)['results']

        for provt in all_provt:
            pt_tpl = {}
            if 'name' in provt:
                name = provt['name']
            else:
                continue
            pt_tpl[name] = self.filter_dump(provt, wanted_keys)
            pto = self.fm.provisioning_templates.show(provt['id'])
            # Remove trailing spaces in template - WA https://github.com/yaml/pyyaml/issues/121
            pt_tpl[name]['template'] = self.rstrip_multilines(pto['template'])
            ret.append(pt_tpl)

        return ret


    def dump_users(self, search=None):
        ret = []
        wanted_keys = [
            "login",
            "firstname",
            "lastname",
            "locale",
            "mail",
            "timezone",
            "admin"
        ]
        all_users = self.fm.users.index(per_page=99999,search=search)['results']
        for user in all_users:
            usr_tpl = {}
            if 'login' in user:
                name = user['login']
            else:
                continue
            usr_tpl[name] = self.filter_dump(user, wanted_keys)
            dd = self.dict_dash(user)
            auths = dd['auth-source-name']
            if (auths == 'Internal'):
                auths = 'INTERNAL'
            usr_tpl[name]['auth-source'] = auths
            ret.append(usr_tpl)

        return ret


    def dump_auth_source_ldap(self, search=None):
        ret = []
        wanted_keys = [
            "name",
            "host",
            "port",
            "base-dn",
            "ldap-filter",
            "tls",
            "onthefly-register",
            "usergroup-sync",
            "attr-firstname",
            "attr-lastname",
            "attr-login",
            "attr-mail",
            "attr-photo",
            "mail",
            "server-type",
            "account",
            "use-netgroups",
            "timezone"
        ]
        all_ldaps = self.fm.auth_source_ldaps.index(per_page=99999,search=search)['results']
        for ldaps in all_ldaps:
            dump_obj = {}
            if 'name' in ldaps:
                name = ldaps['name']
            else:
                continue
            dump_obj[name] = self.filter_dump(ldaps, wanted_keys)
            ret.append(dump_obj)
        return ret


    def dump_usergroups(self, search=None):
        ret = []
        all_groups = self.fm.usergroups.index(per_page=99999,search=search)['results']
        for group in all_groups:
            gobj = {}
            name = group['name']
            gobj[name] = {
                "name": group['name'],
                "admin": group['admin']
            }
            ret.append(gobj)
            # users
            uobj = self.fm.usergroups.users_index(group['id'])['results']
            if (len(uobj)>0):
                gobj[name]['users'] = []
                for user in uobj:
                    add_u = { "name":user['login'] }
                    gobj[name]['users'].append(add_u)
        return ret


    def dump_roles(self, search=None):
        ret = []
        all_filters_index = {}
        all_filters_search_index = {}

        all_filters = self.fm.filters.index(per_page=99999,search=search)['results']
        for filter in all_filters:
            fperms = []
            for perm in filter['permissions']:
                fperms.append(perm['name'])
            all_filters_index[filter['id']] = fperms
            if 'search' in filter:
                if filter['search'] is not None and filter['search'] != '':
                  all_filters_search_index[filter['id']] = filter['search']

        all_roles = self.fm.roles.index(per_page=99999)['results']
        for role in all_roles:
            role_tpl = {}
            if role['origin'] != None:
              continue
            if 'name' in role:
                name = role['name']
            else:
                continue
            role_tpl[name] = {}
            role_tpl[name]['name'] = name
            role_tpl[name]['description'] = role['description']
            role_tpl[name]['permissions'] = []
            robj = self.fm.roles.show(role['id'])
            for filter in robj['filters']:
                for p in all_filters_index[filter['id']]:
                    current_filter = {}
                    current_filter['name'] = p
                    if filter['id'] in all_filters_search_index:
                      current_filter['search'] = all_filters_search_index[filter['id']]
                    role_tpl[name]['permissions'].append(current_filter)

            ret.append(role_tpl)

        return ret


    def dump_compute_resource(self, search=None):
        ret = []
        wanted_keys = [
            "name",
            "description",
            "url",
            "provider",
            "provider-friendly-name",
            "user",
            "tenant",
            "domain",
            "access-key",
            "region",
            "datacenter",
            "server",
            "set-console-password",
            "caching-enabled",
            "display-type",
            "images"
        ]
        wanted_attr_keys = [
            "name",
            "compute-profile-name",
            "attributes"
        ]

        all_cpt_res = self.fm.compute_resources.index(per_page=99999,search=search)['results']
        for res in all_cpt_res:
            res_tpl = {}
            if 'name' in res:
                name = res['name']
            else:
                continue
            try:
                robj = self.fm.compute_resources.show(res['id'])
            except:
                continue
            res_tpl[name] = self.filter_dump(robj, wanted_keys)
            res_tpl[name]['compute-attributes'] = []
            for attr in robj['compute_attributes']:
                res_attr_tpl = self.filter_dump(attr, wanted_attr_keys)
                res_tpl[name]['compute-attributes'].append(res_attr_tpl)
            ret.append(res_tpl)

        return ret


    def dump_compute_profile(self, search=None):
        ret = []
        all_profiles = self.fm.compute_profiles.index(per_page=99999,search=search)['results']
        for profile in all_profiles:
            tpl = {}
            tpl[profile['name']] = { 'name': profile['name'] }
            ret.append(tpl)
        return ret


    def dump_job_template(self, search=None):
        ret = []
        all_jobt = []
        wanted_keys = [
            "name",
            "description-format",
            "locked",
            "audit-comment",
            "job-category",
            "provider-type",
            "snippet",
            "template-inputs"
        ]
        wanted_user_keys = [
            "value",
            "current-user",
            "overridable"
        ]
        try:
            all_jobt = self.fm.job_templates.index(per_page=99999,search=search)['results']
        except:
            pass

        for jobt in all_jobt:
            jt_tpl = {}
            if 'name' in jobt:
                name = jobt['name']
            else:
                continue
            jto = self.fm.job_templates.show(jobt['id'])
            jt_tpl[name] = self.filter_dump(jto, wanted_keys)
            jt_tpl[name]['template'] = self.rstrip_multilines(jto['template'])
            jt_tpl[name]['effective-user'] = self.filter_dump(jto['effective_user'], wanted_user_keys)
            if 'template-inputs' in jt_tpl[name]:
                for input in jt_tpl[name]['template-inputs']:
                    del input['id']
            ret.append(jt_tpl)

        return ret


    def dump_global_parameter(self, search=None):
        ret = []
        wanted_keys = [
            "name",
            "value",
            "parameter-type",
            "hidden-value?"
        ]
        all_params = self.fm.common_parameters.index(per_page=99999,search=search,show_hidden='true')['results']
        for param in all_params:
            param_tpl = {}
            param_tpl[param['name']] = self.filter_dump(param, wanted_keys)
            ret.append(param_tpl)

        return ret


    def dump_bookmark(self, search=None):
        ret = []
        wanted_keys = [
            "name",
            "controller",
            "query",
            "public"
        ]
        all_bm = self.fm.bookmarks.index(per_page=99999,search=search)['results']
        for bm in all_bm:
            bm_tpl = {}
            bm_tpl[bm['controller']+'_'+bm['name']] = self.filter_dump(bm, wanted_keys)
            ret.append(bm_tpl)

        return ret


    def dump_smart_class_parameter(self, search=None):
        ret = []
        wanted_keys = [
            "description",
            "override",
            "parameter-type",
            "hidden-value?",
            "omit",
            "required",
            "validator-type",
            "validator-rule",
            "merge-overrides",
            "merge-default",
            "avoid-duplicates",
            "override-values",
            "override-value-order",
            "use-puppet-default",
            "parameter",
            "default-value",
            "puppetclass-name",
        ]
        wanted_override_keys = [
            "match",
            "value",
            "omit",
            "use_puppet_default",
        ]
        search_query = "override=true"
        if search is not None:
            search_query = "%s and %s" % (search_query, search)
        all_params = self.fm.smart_class_parameters.index(per_page=99999,search=search_query)['results']
        for param in all_params:
            param_tpl = {}
            pobj = self.fm.smart_class_parameters.show(param['id'],show_hidden='true')
            pname = "%s::%s" % (pobj['puppetclass_name'], pobj['parameter'])
            param_tpl[pname] = self.filter_dump(pobj, wanted_keys)
            if 'override-values' in param_tpl[pname]:
                param_tpl[pname]['override-values'] = []
                for ov in pobj['override_values']:
                    ov_tpl = self.filter_dump(ov, wanted_override_keys)
                    param_tpl[pname]['override-values'].append(ov_tpl)
            if pobj['omit'] == True and 'default-value' in param_tpl[pname]:
                del param_tpl[pname]['default-value']
            ret.append(param_tpl)

        return ret


    def dump_organization(self, search=None):
        ret = []
        wanted_keys = [
            "name",
            "title",
            "description",
            "compute-resources",
            "domains",
            "environments",
            "hostgroups",
            "locations",
            "media",
            "parameters",
            "provisioning-templates",
            "ptables",
            "realms",
            "select-all-types",
            "smart-proxies",
            "subnets",
            "users"
        ]
        for org in self.all_org:
            tpl = {}
            tpl[org['name']] = {}
            org_info = self.fm.organizations.show(org['id'])
            
            tpl[org['name']]['select-all-types'] = org_info['select_all_types']
            if not 'User' in org_info['select_all_types']:
                tpl[org['name']]['users'] = []
                for obj in org_info['users']:
                    tpl[org['name']]['users'].append(obj['login'])
            if not 'SmartProxy' in org_info['select_all_types']:
                tpl[org['name']]['smart-proxies'] = []
                for obj in org_info['smart_proxies']:
                    tpl[org['name']]['smart-proxies'].append(obj['name'])
            if not 'Subnet' in org_info['select_all_types']:
                tpl[org['name']]['subnets'] = []
                for obj in org_info['subnets']:
                    tpl[org['name']]['subnets'].append(obj['name'])
            if not 'ComputeResource' in org_info['select_all_types']:
                tpl[org['name']]['compute-resources'] = []
                for obj in org_info['compute_resources']:
                    tpl[org['name']]['compute-resources'].append(obj['name'])
            if not 'Medium' in org_info['select_all_types']:
                tpl[org['name']]['media'] = []
                for obj in org_info['media']:
                    tpl[org['name']]['media'].append(obj['name'])
            if not 'Ptable' in org_info['select_all_types']:
                tpl[org['name']]['ptables'] = []
                for obj in org_info['ptables']:
                    tpl[org['name']]['ptables'].append(obj['name'])
            if not 'ProvisioningTemplate' in org_info['select_all_types']:
                tpl[org['name']]['provisioning-templates'] = []
                for obj in org_info['provisioning_templates']:
                    tpl[org['name']]['provisioning-templates'].append(obj['name'])
            if not 'Domain' in org_info['select_all_types']:
                tpl[org['name']]['domains'] = []
                for obj in org_info['domains']:
                    tpl[org['name']]['domains'].append(obj['name'])
            if not 'Realm' in org_info['select_all_types']:
                tpl[org['name']]['realms'] = []
                for obj in org_info['realms']:
                    tpl[org['name']]['realms'].append(obj['name'])
            if not 'Environment' in org_info['select_all_types']:
                tpl[org['name']]['environments'] = []
                for obj in org_info['environments']:
                    tpl[org['name']]['environments'].append(obj['name'])
            if not 'Hostgroup' in org_info['select_all_types']:
                tpl[org['name']]['hostgroups'] = []
                for obj in org_info['hostgroups']:
                    tpl[org['name']]['hostgroups'].append(obj['name'])
            tpl[org['name']]['locations'] = []
            for obj in org_info['locations']:
                tpl[org['name']]['locations'].append(obj['name'])
            tpl[org['name']]['parameters'] = {}
            for obj in org_info['parameters']:
                tpl[org['name']]['parameters'][obj['name']] = obj['value']
            
            tpl[org['name']] = self.filter_dump(tpl[org['name']], wanted_keys)
            ret.append(tpl)

        return ret


    def dump_location(self, search=None):
        ret = []
        wanted_keys = [
            "name",
            "title",
            "description",
            "compute-resources",
            "domains",
            "environments",
            "hostgroups",
            "media",
            "organizations",
            "parameters",
            "provisioning-templates",
            "ptables",
            "realms",
            "select-all-types",
            "smart-proxies",
            "subnets",
            "users"
        ]
        all_loc = self.fm.locations.index(per_page=99999,search=search)['results']
        for loc in all_loc:
            tpl = {}
            tpl[loc['name']] = {}
            loc_info = self.fm.locations.show(loc['id'])
            
            tpl[loc['name']]['select-all-types'] = loc_info['select_all_types']
            if not 'User' in loc_info['select_all_types']:
                tpl[loc['name']]['users'] = []
                for obj in loc_info['users']:
                    tpl[loc['name']]['users'].append(obj['login'])
            if not 'SmartProxy' in loc_info['select_all_types']:
                tpl[loc['name']]['smart-proxies'] = []
                for obj in loc_info['smart_proxies']:
                    tpl[loc['name']]['smart-proxies'].append(obj['name'])
            if not 'Subnet' in loc_info['select_all_types']:
                tpl[loc['name']]['subnets'] = []
                for obj in loc_info['subnets']:
                    tpl[loc['name']]['subnets'].append(obj['name'])
            if not 'ComputeResource' in loc_info['select_all_types']:
                tpl[loc['name']]['compute-resources'] = []
                for obj in loc_info['compute_resources']:
                    tpl[loc['name']]['compute-resources'].append(obj['name'])
            if not 'Medium' in loc_info['select_all_types']:
                tpl[loc['name']]['media'] = []
                for obj in loc_info['media']:
                    tpl[loc['name']]['media'].append(obj['name'])
            if not 'Ptable' in loc_info['select_all_types']:
                tpl[loc['name']]['ptables'] = []
                for obj in loc_info['ptables']:
                    tpl[loc['name']]['ptables'].append(obj['name'])
            if not 'ProvisioningTemplate' in loc_info['select_all_types']:
                tpl[loc['name']]['provisioning-templates'] = []
                for obj in loc_info['provisioning_templates']:
                    tpl[loc['name']]['provisioning-templates'].append(obj['name'])
            if not 'Domain' in loc_info['select_all_types']:
                tpl[loc['name']]['domains'] = []
                for obj in loc_info['domains']:
                    tpl[loc['name']]['domains'].append(obj['name'])
            if not 'Realm' in loc_info['select_all_types']:
                tpl[loc['name']]['realms'] = []
                for obj in loc_info['realms']:
                    tpl[loc['name']]['realms'].append(obj['name'])
            if not 'Environment' in loc_info['select_all_types']:
                tpl[loc['name']]['environments'] = []
                for obj in loc_info['environments']:
                    tpl[loc['name']]['environments'].append(obj['name'])
            if not 'Hostgroup' in loc_info['select_all_types']:
                tpl[loc['name']]['hostgroups'] = []
                for obj in loc_info['hostgroups']:
                    tpl[loc['name']]['hostgroups'].append(obj['name'])
            tpl[loc['name']]['organizations'] = []
            for obj in loc_info['organizations']:
                tpl[loc['name']]['organizations'].append(obj['name'])
            tpl[loc['name']]['parameters'] = {}
            for obj in loc_info['parameters']:
                if obj != {}:
                    tpl[loc['name']]['parameters'][obj['name']] = obj['value']
            
            tpl[loc['name']] = self.filter_dump(tpl[loc['name']], wanted_keys)
            ret.append(tpl)

        return ret


    def dump_gpg_keys(self, search=None):
        ret = []
        for org in self.all_org:
            all_keys = self.fm.gpg_keys.index(per_page=99999,search=search,organization_id=org['id'])
            if all_keys['results']:
                for key in all_keys['results']:
                    tpl = {}
                    tpl[key['name']] = {}
                    tpl[key['name']]['name'] = key['name']
                    tpl[key['name']]['content'] = key['content'].replace('\r\n', '\n')
                    tpl[key['name']]['organization'] = org['name']
                    ret.append(tpl)

        return ret


    def dump_sync_plans(self, search=None):
        ret = []
        wanted_keys = [
            "name",
            "description",
            "interval",
            "enabled",
            "cron_expression",
            "sync_date"
        ]
        for org in self.all_org:
            all_sp = self.fm.sync_plans.index(per_page=99999,search=search,organization_id=org['id'])
            if all_sp['results']:
                for sp in all_sp['results']:
                    tpl = {}
                    tpl[sp['name']] = self.filter_dump(sp, wanted_keys)
                    tpl[sp['name']]['organization'] = org['name']
                    ret.append(tpl)

        return ret


    def dump_products(self, search=None):
        ret = []
        wanted_keys = [
            "name",
            "label",
            "description"
        ]
        for org in self.all_org:
            all_products = self.fm.products.index(per_page=99999,search=search,organization_id=org['id'])
            if all_products['results']:
                for product in all_products['results']:
                    tpl = {}
                    prod_info = self.fm.products.show(product['id'])
                    tpl[product['name']] = self.filter_dump(prod_info, wanted_keys)
                    if 'gpg_key' in prod_info:
                        tpl[product['name']]['gpg-key'] = prod_info['gpg_key']['name']
                    if prod_info['sync_plan'] != None:
                        tpl[product['name']]['sync-plan'] = prod_info['sync_plan']['name']
                    tpl[product['name']]['organization'] = org['name']
                    ret.append(tpl)

        return ret


    def dump_repos(self, search=None):
        ret = []
        wanted_keys = [
            "name",
            "label",
            "description",
            "content-type",
            "url",
            "arch",
            "mirror-on-sync",
            "verify-ssl-on-sync",
            "checksum-type",
            "download-policy",
            "ssl-ca-cert-id",
            "ssl-client-cert-id",
            "ssl-client-key-id",
            "upstream-username",
            "deb-releases",
            "deb-components",
            "deb-architectures",
            "ignorable-content"
        ]
        for org in self.all_org:
            all_repos = self.fm.repositories.index(per_page=99999,search=search,organization_id=org['id'])
            if all_repos['results']:
                for repo in all_repos['results']:
                    tpl = {}
                    repo_info = self.fm.repositories.show(repo['id'])
                    tpl[repo['name']] = self.filter_dump(repo_info, wanted_keys)
                    tpl[repo['name']]['product'] = repo_info['product']['name']
                    if repo_info['gpg_key'] != None:
                        tpl[repo['name']]['gpg-key'] = repo_info['gpg_key']['name']
                    tpl[repo['name']]['organization'] = org['name']
                    ret.append(tpl)

        return ret


    def dump_lifecycle_environments(self, search=None):
        ret = []
        wanted_keys = [
            "name",
            "label",
            "description"
        ]
        for org in self.all_org:
            try:
                all_env = self.fm.lifecycle_environments.index(per_page=99999,search=search,organization_id=org['id'])
            except:
                continue
            if all_env['results']:
                for env in all_env['results']:
                    tpl = {}
                    if env['library'] == True:
                        continue
                    tpl[env['name']] = self.filter_dump(env, wanted_keys)
                    tpl[env['name']]['organization'] = org['name']
                    ret.append(tpl)

        return ret


    def dump_content_views(self, search=None):
        ret = []
        wanted_keys = [
            "name",
            "label",
            "description",
            "composite",
            "force-puppet-environment",
            "auto-publish",
            "solve-dependencies",
            "puppet-modules",
            "repositories"
        ]
        for org in self.all_org:
            all_cv = self.fm.content_views.index(per_page=99999,search='name != "Default Organization View"',organization_id=org['id'])
            if all_cv['results']:
                for cv in all_cv['results']:
                    tpl = {}
                    cv_info = self.fm.content_views.show(cv['id'])
                    tpl[cv['name']] = self.filter_dump(cv_info, wanted_keys)
                    tpl[cv['name']]['organization'] = org['name']
                    if cv_info['components']:
                        all_comp = []
                        for comp in cv_info['components']:
                            all_comp.append(comp['content_view']['name'])
                        tpl[cv['name']]['components'] = all_comp
                    if 'repositories' in tpl[cv['name']]:
                        if cv_info['composite']:
                            del tpl[cv['name']]['repositories']
                        else:
                            for repo in tpl[cv['name']]['repositories']:
                                del repo['id']
                                del repo['label']
                    if tpl:
                        ret.append(tpl)

        return ret


    def dump_activation_keys(self, search=None):
        ret = []
        wanted_keys = [
            "name",
            "description",
            "unlimited-hosts",
            "max-hosts"
        ]
        for org in self.all_org:
            all_keys = self.fm.activation_keys.index(per_page=99999,search=search,organization_id=org['id'])
            if all_keys['results']:
                for key in all_keys['results']:
                    tpl = {}
                    products = []
                    enabled_repos = []
                    disabled_repos = []
                    key_info = self.fm.activation_keys.show(key['id'])
                    tpl[key['name']] = self.filter_dump(key_info, wanted_keys)
                    tpl[key['name']]['organization'] = org['name']
                    tpl[key['name']]['content-view'] = key_info['content_view']['name']
                    tpl[key['name']]['environment'] = key_info['environment']['name']
                    for prod in key_info['products']:
                        products.append(prod['name'])
                    tpl[key['name']]['products'] = products
                    for repo in key_info['content_overrides']:
                        if repo['value'] == '1':
                            enabled_repos.append(repo['content_label'])
                        else:
                            disabled_repos.append(repo['content_label'])
                    if enabled_repos:
                        tpl[key['name']]['enabled-repos'] = enabled_repos
                    if disabled_repos:
                        tpl[key['name']]['disabled-repos'] = disabled_repos
                    ret.append(tpl)

        return ret
