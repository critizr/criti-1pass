#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import re
import pexpect
import json
import string

from onepassword.one_exceptions import TokenException
from utils import is_unlock, gen_random_string


class OnePassword(object):

    @staticmethod
    def create_password(length=32):
        password_charset = string.ascii_letters + string.digits
        return gen_random_string(password_charset, length=length)

    def __init__(self, login, password, domain, master_key):
        self.login = login
        self.password = password
        self.domain = domain
        self.master_key = master_key
        self._locked = True
        self.vaults = dict()

    # region Private
    @is_unlock
    def _get_template(self, name):
        response = json.loads(pexpect.spawn(u"op get template {name}".format(name=name)).readline())
        return response

    @is_unlock
    def _encode_item(self, template):
        j_data = template if isinstance(template, basestring) else json.dumps(template)
        shell_cmd = u"echo '{}' | op encode".format(j_data)
        child = pexpect.spawn('/bin/sh', ['-c', shell_cmd])
        response = child.readline().strip()
        return response

    # endregion

    def unlock(self, sub_domain, op_session_name):
        cmd = u'op signin {domain} {login} {secret} --shorthand={session_name}'.format(domain=self.domain, login=self.login, secret=self.master_key, session_name=op_session_name)
        child = pexpect.spawn(cmd)
        child.logfile = sys.stdout
        child.expect([u'Enter the password'], timeout=None)
        child.sendline(self.password)
        token = None
        lines = child.readlines()
        op_session = u"OP_SESSION_{}".format(op_session_name)
        regex = r"export {}=\"(.*)\"".format(op_session)
        for l in lines:
            matches = re.match(regex, l)
            if matches:
                token = matches.groups()[0]
                break
        if not token:
            self._locked = True
            raise TokenException(u"Cannot get token after entering password")
        log_child = pexpect.spawn(u"op signin {}".format(sub_domain))
        os.environ[op_session] = token
        log_child.expect([u'Enter the password'], timeout=None)
        log_child.sendline(self.password)
        self.vaults = json.loads(pexpect.spawn('op list vaults').readline())
        self._locked = False

    @is_unlock
    def create_vault(self, name):
        response = json.loads(pexpect.spawn(u"op create vault {name}".format(name=name)).readline())
        return response['uuid']

    @is_unlock
    def get_vaults_names(self):
        return [x['name'] for x in self.vaults if x.get('name')]

    @is_unlock
    def get_vault(self, name):
        return next((x for x in self.vaults if x['name'] == name), None)

    @is_unlock
    def create_login_item(self, email, password, vault_uuid, **kwargs):
        url = kwargs.get('website', u"")
        template = self._get_template('Login')
        title = kwargs.get('title', u"User {}".format(email))
        template['fields'] = [{u'designation': u'username',
                               u'name': u'username',
                               u'type': u'T',
                               u'value': email},
                              {u'designation': u'password',
                               u'name': u'password',
                               u'type': u'P',
                               u'value': password}]
        encoded_item = self._encode_item(template)
        params = {
            'item': encoded_item,
            'url': url,
            'vault': vault_uuid
        }

        cmd = u"op create item Login {item} --vault={vault}".format(**params)
        if title:
            cmd = u"{cmd} --title='{title}'".format(cmd=cmd, title=title)
        if url:
            cmd = u"{cmd} --url='{url}'".format(cmd=cmd, url=url)
        child = pexpect.spawn('/bin/bash', ['-c', cmd])
        response = child.readline().strip()
        return json.loads(response)

    @is_unlock
    def lock(self):
        cmd = u'op signout'
        child = pexpect.spawn(cmd)
        child.readline()
        self._locked = True

