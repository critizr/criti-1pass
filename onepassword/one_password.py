#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import re
import pexpect
import json
import string

from onepassword.one_exceptions import TokenException
from onepassword.utils import is_unlock, gen_random_string


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
        response = json.loads(pexpect.spawn(str("op get template {name}".format(name=name)), encoding='utf-8').readline())
        return response

    @is_unlock
    def _encode_item(self, template):
        j_data = template if isinstance(template, basestring) else json.dumps(template)
        shell_cmd = str("echo '{}' | op encode".format(j_data))
        child = pexpect.spawn('/bin/sh', ['-c', shell_cmd], encoding='utf-8')
        response = child.readline().strip()
        return response

    # endregion

    def unlock(self, sub_domain, op_session_name):
        cmd = 'op signin %s %s %s --shorthand=%s' % (self.domain, self.login, self.master_key, op_session_name)
        child = pexpect.spawn(cmd, encoding='utf-8')
        child.logfile = sys.stdout
        child.expect([u'Enter the password'], timeout=None)
        child.sendline(self.password)
        token = None
        lines = child.readlines()
        op_session = "OP_SESSION_%s" % op_session_name
        regex = r"export %s=\"(.*)\"" % op_session
        for l in lines:
            matches = re.match(regex, str(l))
            if matches:
                token = matches.groups()[0]
                break
        if not token:
            self._locked = True
            raise TokenException("Cannot get token after entering password")
        log_child = pexpect.spawn("op signin {}".format(sub_domain), encoding='utf-8')
        os.environ[str(op_session)] = str(token)
        log_child.expect([u'Enter the password'], timeout=None)
        log_child.sendline(self.password)
        self.vaults = json.loads(pexpect.spawn('op list vaults', encoding='utf-8').readline())
        self._locked = False

    @is_unlock
    def create_vault(self, name):
        response = json.loads(pexpect.spawn(str("op create vault {name}".format(name=name)), encoding='utf-8').readline())
        return response['uuid']

    @is_unlock
    def get_vaults_names(self):
        return [x['name'] for x in self.vaults if x.get('name')]

    @is_unlock
    def get_vault(self, name):
        return next((x for x in self.vaults if x['name'] == name), None)

    @is_unlock
    def create_login_item(self, email, password, vault_uuid, **kwargs):
        url = kwargs.get('website', "")
        template = self._get_template('Login')
        title = kwargs.get('title', "User {}".format(email))
        template['fields'] = [{'designation': 'username',
                               'name': 'username',
                               'type': 'T',
                               'value': str(email)},
                              {'designation': 'password',
                               'name': 'password',
                               'type': 'P',
                               'value': str(password)}]
        encoded_item = self._encode_item(template)
        params = {
            'item': encoded_item,
            'url': url,
            'vault': vault_uuid
        }

        cmd = str("op create item Login {item} --vault={vault}".format(**params))
        if title:
            cmd = str("{cmd} --title='{title}'".format(cmd=cmd, title=title))
        if url:
            cmd = str("{cmd} --url='{url}'".format(cmd=cmd, url=url))
        child = pexpect.spawn('/bin/bash', ['-c', cmd], encoding='utf-8')
        response = child.readline().strip()
        return json.loads(response)

    @is_unlock
    def lock(self):
        cmd = 'op signout'
        child = pexpect.spawn(cmd, encoding='utf-8')
        child.readline()
        self._locked = True

