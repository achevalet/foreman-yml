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
    def dump(self, object=None, search=None):
        dumpdata = {}
        all_objects = []
        # define supported objects (restrict dump functions name)
        supported_objects = [
            'architecture',
            'auth-source-ldap',
            'compute-resource',
            'compute-profile',
            'domain',
            'environment',
            'hosts',
            'hostgroup',
            'job-template',
            'model',
            'media',
            'os',
            'partition-table',
            'provisioning-template',
            'roles',
            'settings',
            'smart-proxy',
            'subnet',
            'users',
            'usergroups',
        ]

        # define target objects
        if object is not None:
            if object not in supported_objects:
                log.log(log.LOG_ERROR, "Object must be one of %s" %supported_objects)
                sys.exit(1)
            all_objects = [object]
        else:
            all_objects = supported_objects

        # dump objects
        for object in all_objects:
            dump_func = getattr(self, 'dump_%s' %object.replace('-', '_'))
            dumpdata[object] = dump_func(search)

        # print the result
        fmyml = { 'foreman': dumpdata }

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

        yml = yaml.dump(fmyml, allow_unicode=True, default_flow_style=False )
        print( (yml) )


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
                hobj = self.fm.hosts.show(host['id'])
                if (len(hobj['parameters'])>0):
                    host_tpl[name]['parameters'] = {}
                    for param in hobj['parameters']:
                        host_tpl[name]['parameters'][param['name']] = param['value']
            except:
                pass

            ret.append(host_tpl)
        return ret


    def dump_hostgroup(self, search=None):
        ret = []
        all_groups = self.fm.hostgroups.index(per_page=99999,search=search)['results']
        for group in all_groups:
            grp_tpl = {}
            if 'name' in group:
                name = group['name']
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
                hobj = self.fm.hostgroups.show(group['id'])
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
            ret.append({ 'name': arch['name'] })
        return ret


    def dump_environment(self, search=None):
        ret = []
        all_envs = self.fm.environments.index(per_page=99999,search=search)['results']
        for env in all_envs:
            ret.append({ 'name': env['name'] })
        return ret


    def dump_os(self, search=None):
        ret = []
        all_os = self.fm.operatingsystems.index(per_page=99999,search=search)['results']
        for os in all_os:
            os_tpl = {}
            if 'description' in os and os['description'] != None:
                name = os['description']
            elif 'name' in os:
                name = os['name']
            else:
                continue
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
            domobj = self.fm.domains.show(dom['id'])
            if (len(domobj['parameters'])>0):
                dom_tpl[name]['parameters'] = {}
                for param in domobj['parameters']:
                    dom_tpl[name]['parameters'][param['name']] = param['value']
            ret.append(dom_tpl)
        return ret


    def dump_smart_proxy(self, search=None):
        ret = []
        all_proxys = self.fm.smart_proxies.index(per_page=99999,search=search)['results']
        for proxy in all_proxys:
            sp_tpl = {}
            if 'name' in proxy:
                name = proxy['name']
            else:
                continue
            sp_tpl[name] = {}
            sp_tpl[name]['name'] = proxy['name']
            sp_tpl[name]['url'] = proxy['url']
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
            sobj = self.fm.subnets.show(subnet['id'])
            if (len(sobj['parameters'])>0):
                subnet_tpl[name]['parameters'] = {}
                for param in sobj['parameters']:
                    subnet_tpl[name]['parameters'][param['name']] = param['value']

            ret.append(subnet_tpl)

        return ret


    def dump_settings(self, search=None):
        ret = []
        all_settings = self.fm.settings.index(per_page=99999,search=search)['results']
        for settings in all_settings:
            set_tpl = {}
            for setting in settings:
                value = settings[setting]
                if value is None or value=='':
                    continue
                if (setting == "name"):
                    set_tpl['name'] = value
                if (setting == "value"):
                    set_tpl['value'] = value
            # only in settings: allways print out value
            if set_tpl.get('value') is None:
                set_tpl['value'] = ""
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
                pt_tpl[name]['layout'] = str(ptobj['layout'])
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
            pt_tpl[name] = {}
            dd = self.dict_dash(provt)
            for setting in dd:
                if setting in wanted_keys:
                    value = dd[setting]
                    if value is None or value=='':
                        continue
                    pt_tpl[name][setting] = value

            pto = self.fm.provisioning_templates.show(dd['id'])
            pt_tpl[name]['template'] = (pto['template'])
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
            robj = self.fm.compute_resources.show(res['id'])
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
            ret.append({ 'name': profile['name'] })
        return ret


    def dump_job_template(self, search=None):
        ret = []
        wanted_keys = [
            "name",
            "description-format",
            "template",
            "locked",
            "audit-comment",
            "job-category",
            "provider-type",
            "snippet",
            "template-inputs"
            #"effective-user"
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
            jt_tpl[name]['effective-user'] = self.filter_dump(jto['effective_user'], wanted_user_keys)
            if 'template-inputs' in jt_tpl[name]:
                for input in jt_tpl[name]['template-inputs']:
                    del input['id']
            ret.append(jt_tpl)

        return ret
