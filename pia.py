#!/usr/bin/env python

import sys
import json
import yaml
import requests
import uuid
import subprocess
import os
import stat
import hashlib

NOOP = False
VERBOSE = True
YAML_CONFFILE=os.path.expanduser('~/.pia.yml')
TRUE = [ 'yes', True, 'true' ]
CA_CERT_PATH = os.path.expanduser('~/.cert')

"""
included_servers:
    - CA Toronto
    - CA Montreal
    - Germany
    - Netherlands
    - US Seattle
    - US New York City
    - US Silicon Valley
"""

yaml_config = """---
pia_username: pxxxxxxx
strong_security: true
pia_tcp: no
included_servers:
    - CA Montreal
"""

def expand_config(yaml_config):
    return yaml_config

def parse_config(yaml_config):
    if os.path.exists(YAML_CONFFILE):
        with open(YAML_CONFFILE, 'r') as fh:
            yaml_config = fh.read()
        config = yaml.load(yaml_config)
        if config.has_key('strong_security') and config['strong_security'] in TRUE:
            sys.stderr.write('Strong encryption used.\n')
            config.update({
                'pia_cert': 'ca.rsa.4096.crt',
                'pia_cipher': 'AES-256-CBC',
                'pia_auth': 'SHA256',
                })
            if config.has_key('pia_tcp') and config['pia_tcp'] in TRUE:
                config['pia_port'] = 501
            else:
                config['pia_port'] = 1197
        else:
            sys.stderr.write('Weak encryption used.\n')
            config.update({
                'pia_cert': 'ca.rsa.2048.crt',
                'pia_cipher': 'AES-128-CBC',
                'pia_auth': 'SHA1',
                })
            if config.has_key('pia_tcp') and config['pia_tcp'] in TRUE:
                config['pia_port'] = 502
            else:
                config['pia_port'] = 1198

    else:
        sys.stderr.write('Creating %s configuration file\n' % YAML_CONFFILE)
        config = yaml.load(yaml_config)
        config['pia_cert_path'] = CA_CERT_PATH
        with open(YAML_CONFFILE, 'w') as fh:
            fh.write(yaml_config)
        sys.stderr.write('Edit the file and rerun this script.\n')
        sys.exit(1)
    return config

def create_vpn_connection(name):
    nmcli = 'nmcli connection add con-name name type vpn ifname tun0 vpn-type openvpn'.split()
    nmcli[4] = '%s' % name
    if VERBOSE:
        nmcli[4] = '"%s"' % name
        print(" ".join(nmcli))
        nmcli[4] = '%s' % name
    if not NOOP:
        r = subprocess.call(nmcli)

def modify_vpn_connection(name,config):
    vpn_data = "ca = {pia_cert_path}/{pia_cert}, remote-cert-tls = server, username = {pia_username}, port = {pia_port}, cipher = {pia_cipher}, remote = {pia_host}, password-flags = 0, auth = {pia_auth}, connection-type = password"
    nmcli = 'nmcli connection modify name vpn.data vpn_data'.split()
    nmcli[3] = '%s' % name
    nmcli[-1] = vpn_data.format(**config)
    if VERBOSE:
        nmcli[3] = '"%s"' % name
        print(" ".join(nmcli))
        nmcli[3] = '%s' % name
    if not NOOP:
        r = subprocess.call(nmcli)

def get_servers():
    r = requests.get('https://www.privateinternetaccess.com/vpninfo/servers?version=24')
    data = json.loads(r.content.split('\n')[0])
    return data

def sha256sum(content):
    return hashlib.sha256(content).hexdigest()

def get_cacert(config):
    cert_file = os.path.join(config['pia_cert_path'], config['pia_cert'])
    url = 'https://www.privateinternetaccess.com/openvpn/%s' % config['pia_cert']
    r = requests.get(url)
    if os.path.exists(cert_file):
        with open(cert_file, 'r') as fh:
            if sha256sum(r.content) != sha256sum(fh.read()):
                if not NOOP:
                    with open(cert_file, 'w') as fh:
                        fh.write(r.content)
        st = os.stat(cert_file).st_mode
        if st & stat.S_IWOTH == 0 or st & stat.S_IWGRP == 0:
            if not NOOP:
                os.chmod(cert_file, int('100644', 8) )
    else:
        with open(cert_file, 'w') as fh:
            fh.write(r.content)

if __name__ == '__main__':
    config = parse_config(yaml_config)
    get_cacert(config)
    data = get_servers()
    for k in data.keys():
        if k != 'info' and data[k]['name'] in config['included_servers']:
            print data[k]['name'] + ': ' + data[k]['dns']

            config['name'] = 'PIA - ' + data[k]['name'],
            config['pia_host'] = data[k]['dns']
            if not NOOP:
                create_vpn_connection(config['name'])
                modify_vpn_connection(config['name'], config)
