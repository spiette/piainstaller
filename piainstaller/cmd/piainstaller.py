#!/usr/bin/env python3

"""
Create a selected list of vpn entries in the Network Manager

# Copyright 2017 Simon Piette under the GPL v2.1
"""

from __future__ import print_function
import sys
import json
import yaml
import subprocess
import os
import stat
import hashlib
import argparse
import logging

import requests

CA_CERT_PATH = os.path.expanduser('~/.cert')
BASE_URL = 'https://www.privateinternetaccess.com'

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


def parse_config(args):
    """
    This will parse a yaml file and complete the various common configuration
    items. If the file doesn't exists, create a sample one.
    """

    yaml_conffile = os.path.expanduser('~/.pia.yml')
    noop = args.noop
    if os.path.exists(yaml_conffile):
        with open(yaml_conffile, 'r') as fh:
            yaml_config = fh.read()
        config = yaml.load(yaml_config)
        if 'strong_security' in config and config['strong_security']:
            sys.stderr.write('Strong encryption used.\n')
            config.update({
                'pia_cert': 'ca.rsa.4096.crt',
                'pia_cipher': 'AES-256-CBC',
                'pia_auth': 'SHA256',
                })
            if 'pia_tcp' in config and config['pia_tcp']:
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
            if 'pia_tcp' in config and config['pia_tcp']:
                config['pia_port'] = 502
            else:
                config['pia_port'] = 1198

    else:
        yaml_config = """---
        pia_username: pxxxxxxx
        strong_security: true
        pia_cert_path: ~/.cert
        pia_tcp: no
        included_servers:
            - CA Montreal
            - CA Toronto
        """
        config = yaml.load(yaml_config)

        config['pia_cert_path'] = CA_CERT_PATH
        if noop is not True:
            sys.stderr.write(
                'Creating configuration file: %s\n' % yaml_conffile)
            with open(yaml_conffile, 'w') as fh:
                fh.write(yaml_config)
                sys.stderr.write('Edit the file and rerun this script.\n')
        else:
            sys.stderr.write('Not creating template file. Rerun the script '
                             'without --noop option to create a configuration '
                             'file\n.')
        sys.exit(1)
    return config


def create_vpn_connection(args, name):
    """
    Create a new OpenVPN connection
    """
    nmcli = ("nmcli connection add con-name name " +
             "type vpn ifname tun0 vpn-type openvpn").split()
    nmcli[4] = '%s' % name
    logging.info(" ".join(nmcli))
    if not args.noop:
        return subprocess.call(nmcli)


def modify_vpn_connection(args, name, config):
    """
    Set an OpenVPN connection attributes
    """
    vpn_data = ("ca = {pia_cert_path}/{pia_cert}, "
                "remote-cert-tls = server, "
                "username = {pia_username}, "
                "port = {pia_port}, "
                "cipher = {pia_cipher}, "
                "remote = {pia_host}, "
                "password-flags = 0, "
                "auth = {pia_auth}, "
                "comp-lzo = yes, "
                "connection-type = password")
    nmcli = 'nmcli connection modify name vpn.data vpn_data'.split()
    nmcli[3] = '%s' % name
    nmcli[-1] = vpn_data.format(**config)
    logging.info(" ".join(nmcli))
    if not args.noop:
        return subprocess.call(nmcli)


def get_servers():
    """
    Retrieve the latest server list
    """
    url = '{baseurl}/vpninfo/servers?version=24'.format(baseurl=BASE_URL)
    r = requests.get(url)
    data = json.loads(r.content.decode().split('\n')[0])
    return data


def sha256sum(content):
    """
    Simple wrapper for return the hexdigest of a sha256 hash
    """
    if isinstance(content, str):
        content = content.encode('utf-8')
    return hashlib.sha256(content).hexdigest()


def get_cacert(args, config):
    """
    Ensure the CA cert file is at the right location, have the proper
    permissions and contains the proper certificate. Idempotent.
    """
    try:
        cert_file = os.path.join(
            os.path.expanduser(config['pia_cert_path']),
            config['pia_cert'])
    except KeyError:
        sys.stderr.write('Missing pia_cert_path in the configuration file.\n')
    url = '{baseurl}/openvpn/{cert}'.format(
        baseurl=BASE_URL,
        cert=config['pia_cert'])
    logging.info('GET {}'.format(url))
    r = requests.get(url)
    if os.path.exists(cert_file):
        with open(cert_file, 'r', encoding='utf-8') as fh:
            if sha256sum(r.content) != sha256sum(fh.read()):
                if not args.noop:
                    with open(cert_file, 'w', encoding='utf-8') as fh:
                        fh.write(r.content)
        st = os.stat(cert_file).st_mode
        if st & stat.S_IWOTH == 0 or st & stat.S_IWGRP == 0:
            if not args.noop:
                os.chmod(cert_file, int('100644', 8))
    else:
        with open(cert_file, 'w') as fh:
            fh.write(r.content)


def parse_args():
    " parse command-line arguments "
    parser = argparse.ArgumentParser(
        description='Create PIA VPN connections in the NetworkManager')
    parser.add_argument('-v', '--verbose', action='store_true', default=False,
                        help='print out the nmcli commands')
    parser.add_argument('-n', '--noop', action='store_true', default=False,
                        help='run with no changes made')

    args = parser.parse_args()
    datefmt = '%m/%d/%Y %I:%M:%S %p %Z'
    if args.noop is True:
        args.verbose = True
    if args.verbose is True:
        logging.basicConfig(level=logging.INFO,
                            format='%(asctime)s %(message)s', datefmt=datefmt)
    return args


def main():
    " main function "
    args = parse_args()
    config = parse_config(args)
    get_cacert(args, config)
    data = get_servers()
    for k in data.keys():
        if k != 'info' and data[k]['name'] in config['included_servers']:
            print(data[k]['name'] + ': ' + data[k]['dns'])

            config['name'] = 'PIA - ' + data[k]['name'],
            config['pia_host'] = data[k]['dns']
            if create_vpn_connection(args=args, name=config['name']) == 0:
                modify_vpn_connection(args=args,
                                      name=config['name'],
                                      config=config)

if __name__ == '__main__':
    main()
