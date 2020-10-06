#!/usr/bin/python
#
# Copyright (c) 2016-2018 NetApp, Inc., All Rights Reserved
#
# Overview:
#   Script to configure a StorageGRID Appliance after networking has been
#   established.
#
#   Exit status:
#   0 - Script executed successfully
#   1 - There were unknown results, review the output
#   2 - StorageGRID Appliance not in install mode or install cannot continue
#   3 - StorageGRID Appliance time-out (could not connect to the appliance)
#   5 - Inconsistent data, review the output
#
# NOTE:
#   This script has been verified with Python versions: 2.7, and 3.5
#

import argparse
import errno
import json
import logging
import os
import re
import signal
import socket
import subprocess
import sys
import traceback
import types
from time import localtime, time, sleep, strftime

# Check if this environment supports SSL.
# Installer firmware 3.2 and later requires HTTPS for all API calls
_has_ssl_support = False
try:
    import ssl
    _has_ssl_support = True
except ImportError:
    # Install a fake ssl module instead
    # TODO: Maybe just pass instead
    ssl = types.ModuleType("ssl")

if sys.version_info < (3, 0):
    import urllib2 as urllib_request
    import urllib2 as urllib_error
    import urllib2 as urllib_parse
else:
    import urllib.request as urllib_request
    import urllib.error as urllib_error
    import urllib.parse as urllib_parse
    basestring = str

VERSION = "3.4"

# Define structure for interacting with v2 APIs
DEV = {
    'grid':
        {
            'api': 'data',
            'display': 'Grid Network',
            'route': 'grid-route'
        },
    'admin':
        {
            'api': 'mgmt',
            'display': 'Admin Network',
            'route': 'admin-route'
        },
    'client':
        {
            'api': 'clnt',
            'display': 'Client Network',
            'route': 'client-route'
        }}

# Alias entries for interacting with v1 APIs
DEV['br0'] = DEV['grid']
DEV['br1'] = DEV['admin']
DEV['br2'] = DEV['client']

API_INSECURE_PORT = 8080
API_SECURE_PORT = 8443


class AttrDict(dict):
    '''Emulate dictionary values as attributes to simulate argparse.'''
    def __init__(self, *args, **kwargs):
        super(AttrDict, self).__init__(*args, **kwargs)
        self.__dict__ = self


class SmartFormatter(argparse.HelpFormatter):
    '''Add capability to split help on LF'''
    def _split_lines(self, text, width):
        # Update width based on terminal size
        try:
            width = int(subprocess.check_output(['stty', 'size'], stderr=subprocess.STDOUT).split()[1]) - 26
        except(ValueError, IndexError, subprocess.CalledProcessError):
            width = 80 - 26

        lines = []
        if '\n' in text:
            for entry in text.splitlines():
                lines += argparse.HelpFormatter._split_lines(self, entry, width)
            return lines
        # this is the RawTextHelpFormatter._split_lines
        return argparse.HelpFormatter._split_lines(self, text, width)


class ArgParser(argparse.ArgumentParser):
    ''' Inherit from argparse.ArgumentParser so we can overload the error method'''
    def error(self, message):
        '''Redefine error method to print full usage when an error occurs'''
        sys.stderr.write('error: %s\n' % message)
        self.print_help()
        sys.exit(1)


def parse_args():
    '''Parse the command-line arguments.
    Parsed arguments will be available in the global "args".'''

    global args
    global install_args
    global monitor_args

    # Use our parser with overloaded error method
    parser = ArgParser(description='Script to configure a StorageGRID Appliance after networking has been established.',
                       formatter_class=SmartFormatter)
    # Optional global arguments
    parser.add_argument('--ignore-warnings',
                        help='Ignore non-fatal configuration changes or issues including: ' +
                        'Changing the address of the interface currently being used to configure the ' +
                        'appliance (--admin-cidr, --client-cidr and ' +
                        '--grid-cidr).', action='store_true')
    parser.add_argument('--logfile',
                        help='Log file for verbose logging (--verbose not required).',
                        metavar='LOGFILE')
    parser.add_argument('--poll-time',
                        help='Seconds to sleep during polling intervals (default 10).',
                        type=int, default=10, metavar='SECONDS')
    parser.add_argument('-v', '--verbose',
                        help='Verbose output (shows raw http calls in <STDOUT>).', action='store_true')
    parser.add_argument('--version',
                        help='Displays the version of StorageGRID Appliance this script was written for.',
                        action='store_true')
    parser.add_argument('--no-insecure',
                        help='Only allow secure HTTPS communication with the appliance',
                        action='store_true')

    subparsers = parser.add_subparsers(help='sub-command -h|--help for detailed help on each command.')

    # Create all sub-commands
    configure = subparsers.add_parser('configure', help='sub-command to configure networking parameters.',
                                      formatter_class=SmartFormatter)
    install = subparsers.add_parser('install', help='sub-command to start the StorageGRID installation.',
                                    formatter_class=SmartFormatter)
    monitor = subparsers.add_parser('monitor', help='sub-command to monitor a StorageGRID installation.',
                                    formatter_class=SmartFormatter)
    reboot = subparsers.add_parser('reboot', help='sub-command to reboot a StorageGRID Appliance.',
                                   formatter_class=SmartFormatter)

    # Required positional arguments (All sub-commands require SGA-INSTALL-IP)
    for sub_cmd in [configure, install, monitor, reboot]:
        sub_cmd.add_argument('sga_install_ip', help='The IP address of management port 1 on the controller (the 1Gb RJ45 port ' +
                             'on the left), used to connect the appliance to the Admin Network.',
                             metavar='SGA-INSTALL-IP')

    # Confirgure sub-command optional arguments
    configure.set_defaults(parser='configure')
    configure.add_argument('-a', '--admin-ip',
                           help='The IP address of the primary Admin Node for a StorageGRID grid. The appliance ' +
                           'connects to the primary Admin Node over the Grid Network. If you have more than one grid, set this ' +
                           'field to "discover" to return a list of all available primary Admin Nodes.',
                           metavar='PRIMARY-ADMIN-NODE-IP')

    for dev in devices:
        # For admin and client networks (not grid)
        if dev != 'grid':
            configure.add_argument('--' + dev + '-network-state',
                                   help='Set the state of ' + DEV[dev]['display'] + '. Enable or disable the ' +
                                   DEV[dev]['display'] + '.',
                                   choices=['enabled', 'disabled'], metavar='enabled|disabled')

        configure.add_argument('--' + dev + '-cidr',
                               help='Update the IP and network (in CIDR format) of the "' + DEV[dev]['display'] +
                               '" on the appliance.' +
                               '\nNote: Set to "DHCP" for automatic IP addressing.', metavar='CIDR')
        configure.add_argument('--' + dev + '-gateway',
                               help='Set a gateway IP for the ' + DEV[dev]['display'] + '.',
                               metavar='IP')
        # For grid and admin networks (not client)
        if dev != 'client':
            configure.add_argument('--add-' + dev + '-subnet',
                                   help='Add a subnet (specified as "IP/MASK" in CIDR format) to the ' + DEV[dev]['display'] + '.' +
                                   '\nNote: You can specify this parameter multiple times.',
                                   metavar='CIDR', action='append', default=[])
            configure.add_argument('--del-' + dev + '-subnet',
                                   help='Delete a subnet (specified as "IP/MASK" in CIDR format) from the ' + DEV[dev]['display'] + '.' +
                                   '\nNote: You can specify this parameter multiple times.',
                                   metavar='CIDR', action='append', default=[])
        configure.add_argument('--' + dev + '-bond-mode',
                               help='Set the ' + DEV[dev]['display'] + ' bond mode in fixed port configuration to either ' +
                               '"active-backup" or "lacp".', choices=['active-backup', 'lacp', 'no-bond'],
                               metavar='active-backup|lacp|no-bond')
        configure.add_argument('--' + dev + '-vlan-id',
                               help='Set the VLAN ID for the ' + DEV[dev]['display'] + '. A VLAN ID is required when using ' +
                               'aggregate mode. Setting to "novlan" will switch the interface to untagged mode.',
                               metavar='VLAN ID|novlan')
        configure.add_argument('--add-' + dev + '-route',
                               help='Add a networking route (specified as "IP/MASK" in CIDR format) ' +
                               'to the ' + DEV[dev]['display'] + '.' +
                               '\nNote: You can specify this parameter multiple times.' +
                               '\nCompatibility: Use on StorageGRID Appliance prior to 2.0.',
                               metavar='\'CIDR via gateway\'', action='append', default=[])
        configure.add_argument('--del-' + dev + '-route',
                               help='Delete a networking route (specified as "IP/MASK" in CIDR format) from the ' +
                               DEV[dev]['display'] + '.' +
                               '\nNote: You can specify this parameter multiple times.' +
                               '\nCompatibility: Use on StorageGRID Appliance prior to 2.0.',
                               metavar='\'CIDR via gateway\'', action='append', default=[])

    configure.add_argument('--forceConfig-flag',
                           help='Set the forceConfig flag to "true" to reformat all attached storage (removes any storage ' +
                           'data). Set the flag to "false" to preserve data on the attached storage.',
                           choices=['true', 'false'], metavar='true|false')
    configure.add_argument('--port-configuration',
                           help='Set the port configuration. Select "aggregate" to add all four ports to a single LACP ' +
                           'bond. Then, specify a VLAN ID for both the Grid and Client Networks. Select "fixed" to use ports 2 ' +
                           'and 4 for the Grid Network and ports 1 and 3 for the Client Network.',
                           choices=['aggregate', 'fixed'], metavar='aggregate|fixed')
    configure.add_argument('--link-speed',
                           help='Set the link speed for the four ports used by the Grid and Client Networks.',
                           choices=['10GbE', '25GbE'], metavar='10GbE|25GbE')
    configure.add_argument('-n', '--node-name',
                           help='Set the StorageGRID node name for this appliance.',
                           metavar='NODE_NAME')
    configure.add_argument('--raid-mode',
                           help='The RAID mode that will be used.' +
                           '\nNote: Appliance models with fewer than 60 drives do not support RAID6 mode. The RAID mode will ' +
                           'be verified at run time.',
                           choices=['ddp', 'raid6'], metavar='ddp|raid6')
    configure.add_argument('-i', '--install',
                           help='Installation is performed after configuration. ' +
                           '\nNote: You can specify any of the install sub-command options.',
                           action='store_true')

    # Install sub-command optional arguments
    install.set_defaults(parser='install', install=True)
    install.add_argument('-m', '--monitor',
                         help='Monitor the installation of the StorageGRID installation after installation starts. ' +
                         '\nNote: You can specify any of the monitor sub-command options.',
                         action='store_true')
    install.add_argument('-t', '--timeout',
                         help='Minutes to wait for the primary Admin Node to become available to the ' +
                         'StorageGRID Appliance (default 10).',
                         type=int, default=10, metavar='MINUTES')
    install.add_argument('-s', '--skip-monitor',
                         help='Monitoring the progress of the installation occurs by default. ' +
                         'Specifying this option skips monitoring after installation starts.',
                         action='store_true')

    # Monitor sub-command optional arguments
    monitor.set_defaults(parser='monitor', monitor=True)
    monitor.add_argument('--monitor-delta',
                         help='Summarized monitoring information; an alternative to the tabular output.',
                         action='store_true')
    monitor.add_argument('--monitor-storagegrid-install',
                         help='By default, installation monitoring exits once the "Install ' +
                         'StorageGRID Software" task has started. This option continues monitoring ' +
                         'until the appliance joins the StorageGRID grid.',
                         action='store_true')

    # reboot sub-command optional arguments
    reboot.set_defaults(parser='reboot')

    # Check the --version flag here (ignoring missing required arguments)
    if '--version' in sys.argv:
        log.info("Version: " + VERSION)
        sys.exit(0)

    # Parse the base options. Arguments for other sub-options will be left in (rest)
    args, rest = parser.parse_known_args()

    # Parseargs hack... If '-t' is in rest, then args.sga_install_ip has the -t param
    # and the argument following -t has the sga_install_ip (need to swap them)
    # This is because parse_known_args assumes that unknown argumets don't take a value
    if '-t' in rest:
        # First make sure there's a candidate argument after -t
        candidate_index = rest.index('-t') + 1
        if candidate_index >= len(rest):
            parser.error('too few arguments')
        candidate_value = rest[candidate_index]
        # Should be a non-option parameter (not start with '-')
        if candidate_value.startswith('-'):
            parser.error('Invalid parameter for -t (' + candidate_value + ').')
        # Swap the arguments
        rest[candidate_index] = vars(args)['sga_install_ip']
        vars(args)['sga_install_ip'] = candidate_value

    # Python3 misses the basic usage when no arguments are passed.
    try:
        args.parser
    except AttributeError:
        parser.error('too few arguments')

    # See if the "install" sub-command was used
    if args.parser == 'install':
        install_args = args
    # Was not the main sub-command, see if it was called out as an argument (--install)
    elif args.parser == 'configure' and args.install:
        # Parse the install arguments. Pass the SGA-INSTALL-IP as the first arg
        install_args, rest = install.parse_known_args([args.sga_install_ip] + rest)
    else:
        # Intall will not be performed, create variables for work flow
        install_args = AttrDict({'install': False, 'monitor': False, 'timeout': 10})

    # See if the "monitor" sub-command was used
    if args.parser == 'monitor':
        monitor_args = args
    # Was not the main sub-command, see if it was called out as an install argument (--monitor)
    elif install_args.monitor:
        # Parse the monitor arguments. Pass the SGA-INSTALL-IP as the first arg
        monitor_args, rest = monitor.parse_known_args([args.sga_install_ip] + rest)
    else:
        # Monitor not called out, so do not monitor
        monitor_args = AttrDict({'monitor': False})
        # However if we're doing an install and --skip-monitor was not specified, then monitor
        if install_args.install and not install_args.skip_monitor:
            monitor_args = AttrDict({'monitor': True, 'monitor_delta': False, 'monitor_storagegrid_install': False})

    # There should be no options left over in (rest)
    if '--monitor' in rest:
        install.error('Option --monitor requires --install in configure mode.')
    if rest:
        parser.error('Unrecognized arguments: ' + ' '.join(rest))

    if args.parser == 'install' and monitor_args.monitor and install_args.skip_monitor:
            raise DataInconsistencyError('Cannot specify both --skip-monitor and --monitor.\n' +
                                         '  Specify --help for detailed usage.')

    # Verify the sga_install_ip is a valid format
    IPv4(args.sga_install_ip)

    if args.parser == 'configure':
        # Verify the IP format specified as PRIMARY-ADMIN-NODE-IP
        if args.admin_ip and args.admin_ip != 'discover':
            IPv4(args.admin_ip)

        # Verify all the IP formats specified for changes to the device interfaces
        for cidr_arg in [args.grid_cidr, args.admin_cidr, args.client_cidr]:
            # These are optional arguments, do not check if not passed
            if cidr_arg and cidr_arg != 'DHCP':
                IPv4(cidr_arg, 'CIDR')

        # Verify all the route formats specified for routing changes (these are all lists)
        for route in args.add_grid_route + args.add_admin_route + args.add_client_route +\
                args.del_grid_route + args.del_admin_route + args.del_client_route:
            match = re.match('^(.+) via (.+)$', route)
            if not match:
                raise DataInconsistencyError('Route (' + route + ') is not a valid format.\n' +
                                             '  Update to "CIDR via gateway".')
            network = match.group(1)
            gateway = match.group(2)
            try:
                if network != 'default':
                    IPv4(network, 'NETWORK')
                IPv4(gateway)
            except:
                # Catching the exception in order to show the original "route" string
                log.error('Invalid route (' + route + ').')
                raise

        # Verify the node name is valid
        if args.node_name:
            valid, helptext = validate_node_name(args.node_name)
            if not valid:
                raise DataInconsistencyError("'" + args.node_name +
                                             "' is not a valid node name. " +
                                             helptext)

        for vlanid in [args.grid_vlan_id, args.admin_vlan_id, args.client_vlan_id]:
            try:
                if vlanid and vlanid != "novlan":
                    if (int(vlanid) < 0) or (int(vlanid) > 4095):
                        raise DataInconsistencyError("'" + vlanid + "' is not a valid VLAN ID. ")
            except (AttributeError, ValueError):
                raise DataInconsistencyError("'" + vlanid + "' is not a valid VLAN ID. ")

        for dev in ['admin', 'client']:
            args_copy = list(vars(args))
            # Remove the admin-ip option and network-state from the copy
            args_copy.remove('admin_ip')
            args_copy.remove(dev + '_network_state')
            # If we're disabling this device...
            if vars(args).get(dev + '_network_state') == 'disabled':
                # Find any args which would modify this device
                dev_args = filter(re.compile('.*' + dev + '.*').match, args_copy)
                for arg in dev_args:
                    # See if there is a corresponding value
                    if vars(args).get(arg):
                        raise DataInconsistencyError('Cannot specify "--' + dev + '-network-state disabled" and the "--' +
                                                     arg.replace('_', '-') + '" option or other options which would modify the ' +
                                                     DEV[dev]['display'] + '.\n  Specify --help for detailed usage.')


def get_version(try_version):
    timeout = time() + install_args.timeout * 60
    log.info('Connecting to ' + sga.base_url + ' (Checking version and connectivity.)')
    sga.quiet = False
    while True:
        try:
            versions = json.loads(sga.call('GET', '/versions'))
            if try_version in versions['data']:
                sga.base_uri = '/api/v' + str(try_version)
                version = versions['apiVersion']
                break
            elif sga.secure == False and versions.get('deprecated') and versions['data'] == []:
                # Handle the transition to HTTPS in firmware version 3.2 which reports [] for
                # the list of supported versions on HTTP and has the deprecated flag set
                log.info("Upgrading request to HTTPS and retrying.", lf=True)
                sga.upgrade_to_https()
                log.info('Connecting to ' + sga.base_url + ' (Checking version and connectivity.)')
            else:
                raise DataInconsistencyError('The API is too new for this script.\n' +
                                             '  Download a newer version from the StorageGRID Appliance.\n' +
                                             '  ' + sga.base_url + '/configure-sga.py')
        # Handle connection refused errors, which might indicate needing to switch ports
        except urllib_error.URLError as e:
            if e.reason and getattr(e.reason, "errno", None) == errno.ECONNREFUSED:
                log.info("Connection Refused", lf=True)
                if sga.secure:
                    if not args.no_insecure:
                        log.info("Downgrading to HTTP request and retrying.", lf=True)
                        sga.downgrade_to_http()
                else:
                    log.info("Upgrading request to HTTPS and retrying.", lf=True)
                    sga.upgrade_to_https()
                log.info('Connecting to ' + sga.base_url + ' (Checking version and connectivity.)')
            else:
                # Unknown other URLError reported, pass it up to the caller
                log.exception(e)
                raise
            sleep(args.poll_time)
        except SgaInstaller.ResponseError as e:
            if str(e) == '404':
                try:
                    # Couldn't communicate with v2 protocol, try v1 protocol
                    sga.set_protocol_v1()
                    version = json.loads(sga.call('GET', '/sys/pgeVersion'))['version']
                except SgaInstaller.ResponseError as e:
                    if str(e) == '404':
                        version = '1.3'
                        pass
                    else:
                        raise ApplianceNotReadyError('Received unexpected reponse from the appliance:\n' +
                                                     '  Received: ' + str(e))
                break
            elif str(e)[0] == '5':
                if time() > timeout:
                    raise ApplianceNotReadyError('Timed out while trying to determine the version via GET /versions:\n' +
                                                 '  Received: ' + str(e))
                else:
                    if sga.quiet:
                        log.info('.', False)
                    else:
                        log.info('Unable to determine the version. Retrying.')
                        sga.quiet = True
                    # Should be a transient error, so just keep retrying with a delay in between.
                    sleep(args.poll_time)
    # Grab major and minor numbers from the version string
    sga.quiet = False
    version = version.split('.')[:2]
    return (int(version[0]), int(version[1]))


def validate_node_name(value):
    '''1..32 characters, alphanum plus hyphen, cannot start/end with hyphen
       or be all numbers.
    '''
    hlp = 'A StorageGRID node name should contain between 1 and 32 characters,\
 including only letters (at least one letter is required), numbers, and hyphens,\
 and must not start or end with a hyphen.'
    res = False
    if (value and len(value) >= 1 and len(value) <= 32):
        if re.match('^[0-9A-Za-z-]+$', value):
            if re.match('^[^-].*', value):
                if re.match('.*[^-]$', value):
                    if re.match('.*[A-Za-z].*', value):
                        res = True
    return (res, hlp)


def configure_sga_v2():
    '''Configure the StorageGRID Appliance.'''

    global admin_connection
    global link_config
    global networks
    global system_config
    global system_info

    # add-grid-route, add-admin-route, add-client-route, del-grid-route, del-admin-route and del-grid-route,
    # are no longer supported when interacting with 2.0 firmware (raise an error)
    for dev in devices:
        for task in ['add', 'del']:
            if vars(args).get(task + '_' + dev + '_route'):
                # add-client-subnet and del-client-subnet do not exist
                subnet_option = ' and the --' + task + '-' + dev + '-subnet option' if dev != 'client' else ''
                raise DataInconsistencyError('The --' + task + '-' + dev + '-route is not supported by the firmware ' +
                                             'version on this StorageGRID Appliance. ' +
                                             'Use the --' + dev + '-gateway option' + subnet_option + '.')

    # Update the admin IP
    if args.admin_ip:
        if system_info.get('maintenanceMode'):
            raise DataInconsistencyError(
                'This node is in maintenance mode. You cannot change the admin-ip.\n' +
                'Perform any required maintenance procedures, then reboot the node to resume normal operation.')
        # Tell the appliance where the PRIMARY-ADMIN-NODE-IP is
        log.info('Updating primary Admin Node (StorageGRID Installer) to ' + args.admin_ip)
        if args.admin_ip == 'discover':
            ip = None
            discover = True
        else:
            ip = args.admin_ip
            discover = False
        sga.call('PUT', '/admin-connection', {'ip': ip, 'useDiscovery': discover})

    # Update the link config: Bonds, VLAN, state (these all affect the /link-config
    if args.port_configuration or args.link_speed or args.admin_network_state or args.client_network_state or \
            args.grid_bond_mode or args.client_bond_mode or args.grid_vlan_id or args.client_vlan_id:

        # Update the link-config
        update_link_config()

        # Refresh the link_config structure
        log.info('Requesting updated link config')
        link_config = json.loads(sga.call('GET', '/link-config'))['data']
        # Refresh the networks structure
        log.info('Requesting updated networking device configurations')
        networks = json.loads(sga.call('GET', '/networks'))['data']

    # Make network changes (these all affect the /networks API)
    if args.grid_cidr or args.admin_cidr or args.client_cidr or \
            args.del_admin_subnet or args.del_grid_subnet or \
            args.add_admin_subnet or args.add_grid_subnet or \
            args.grid_gateway or args.admin_gateway or args.client_gateway:

        for dev in devices:
            # Change network interface address
            if vars(args).get(dev + '_cidr'):
                change_interface_ip_v2(vars(args)[dev + '_cidr'], dev)

            # Make routing additions
            if vars(args).get('add_' + dev + '_subnet'):
                add_subnets(vars(args)['add_' + dev + '_subnet'], dev)

            # Make routing deletions
            if vars(args).get('del_' + dev + '_subnet'):
                del_subnets(vars(args)['del_' + dev + '_subnet'], dev)

            # Set gateway on devices
            if vars(args).get(dev + '_gateway'):
                set_gateway(vars(args)[dev + '_gateway'], dev)

        # Refresh the networks structure
        log.info('Requesting updated networking device configurations')
        networks = json.loads(sga.call('GET', '/networks'))['data']

    # Set node name and raid mode via system-config
    if args.node_name or args.raid_mode:
        if system_info.get('maintenanceMode') and args.raid_mode:
            raise DataInconsistencyError(
                'This node is in maintenance mode. You cannot change the raid-mode.\n' +
                'Perform any required maintenance procedures, then reboot the node to resume normal operation.')
        if system_info.get('maintenanceMode') and args.node_name:
            raise DataInconsistencyError(
                'This node is in maintenance mode. You cannot change the node-name.\n' +
                'Perform any required maintenance procedures, then reboot the node to resume normal operation.')
        set_system_config(args.node_name, args.raid_mode)
        system_config = json.loads(sga.call('GET', '/system-config'))['data']

    if args.forceConfig_flag:
        if system_info.get('maintenanceMode'):
            raise DataInconsistencyError(
                'This node is in maintenance mode. You cannot set the forceConfig-flag.\n' +
                'Perform any required maintenance procedures, then reboot the node to resume normal operation.')
        if args.forceConfig_flag == 'true':
            resp = sga.call('PUT', '/debug-flags', {'forceClean': True})
            print_hashed(['All storage attached to this appliance will be reformatted,',
                          'causing all data to be lost.'])
        else:
            resp = sga.call('PUT', '/debug-flags', {'forceClean': False})
            print_hashed(['The storage attached to this appliance will not be reformatted.',
                          'Any existing data will be preserved.'])

    # All of these could affect DHCP and/or the admin_connection
    if args.admin_ip or args.port_configuration or args.link_speed or \
            args.admin_network_state or args.client_network_state or \
            args.grid_bond_mode or args.client_bond_mode or args.grid_vlan_id or args.client_vlan_id or \
            args.grid_cidr or args.admin_cidr or args.client_cidr or \
            args.del_admin_subnet or args.del_grid_subnet or \
            args.add_admin_subnet or args.add_grid_subnet or \
            args.grid_gateway or args.admin_gateway or args.client_gateway:
        # Confirm we get a DHCP address (any of the above parameters could cause DHCP to be re-initialized)
        for dev in devices:
            if networks['interfaces'].get(dev):
                wait_for_dhcp_v2(dev, False)
        # Any of the network changes could cause connectivity chages with the admin node
        admin_connection = json.loads(sga.call('GET', '/admin-connection'))['data']
        # Check for up to 60 seconds, don't fail if we don't get a connection
        wait_for_primary_admin_v2(60, False)


def configure_sga_v1(networking):
    '''Configure the StorageGRID appliance.'''

    # Admin Network enabled/disabled became available in 2.0 (since this is v1 - just raise an error)
    if args.admin_network_state:
        raise DataInconsistencyError(
            '''The firmware on this StorageGRID Appliance does not allow you to enable or disable the Admin Network.
            You can use the StorageGRID Appliance Installer to perform this configuration later.''')

    # This script does not support discovery on v1 (raise an error)
    if args.admin_ip == 'discover':
        raise DataInconsistencyError(
            '''This script does not support Admin Node discovery for firmware prior to 2.0.
            You can perform Admin Node discovery using the NetApp StorageGRID Appliance Installer GUI.''')

    # admin-gateway, grid-gateway and client-gateway became available in 2.0 (since this is v1 - just raise an error)
    for dev in ['admin', 'grid', 'client']:
        if vars(args).get(dev + '_gateway'):
            raise DataInconsistencyError('The firmware on this appliance does not support the ' +
                                         '--' + dev + '-gateway option. Instead, use the --add-' + dev + '-route option.')

    for dev in ['admin', 'grid']:
        # add-admin-subnet and add-grid-subnet became available in 2.0 (since this is v1 - just raise an error)
        if vars(args).get('add_' + dev + '_subnet'):
            raise DataInconsistencyError('The firmware on this appliance does not support the ' +
                                         '--add-' + dev + '-subnet option. Instead, use the --add-' + dev + '-route option.')

        # del-admin-subnet and del-grid-subnet became available in 2.0 (since this is v1 - just raise an error)
        if vars(args).get('del_' + dev + '_subnet'):
            raise DataInconsistencyError('The firmware on this appliance does not support the ' +
                                         '--del-' + dev + '-subnet option. Instead, use the --del-' + dev + '-route option.')

    # admin-bond-mode became available in 2.0 (since this is v1 - just raise an error)
    if args.admin_bond_mode:
        raise DataInconsistencyError('The firmware on this appliance does not support the ' +
                                     '--admin-bond-mode option.')

    # link-speed became available in 2.0 (since this is v1 - just raise an error)
    if args.link_speed:
        raise DataInconsistencyError('The firmware on this appliance does not support the ' +
                                     '--link-speed option.')

    # raid-mode became available in 2.0 (since this is v1 - just raise an error)
    if args.raid_mode:
        raise DataInconsistencyError(
            '''This script does not support RAID mode changes for firmware prior to 2.0.
            You can perform RAID mode changes using the NetApp StorageGRID Appliance Installer GUI.''')

    # Client Network and node name became available in 1.5
    if version < (1, 5) and (args.client_cidr or args.add_client_route or args.del_client_route or args.node_name):
        raise DataInconsistencyError(
            '''The firmware on this appliance does not include support
            for configuring Client Network parameters or StorageGRID node name. You can
            perform this configuration later in the installation process, using the
            StorageGRID installation GUI or the configure-storagegrid.py tool.''')

    # Client Network enabled/disabled became available in 1.7
    if version < (1, 7) and args.client_network_state:
        raise DataInconsistencyError(
            '''The firmware on this appliance does not include support for
            enabling/disabling Client Network. You can perform this configuration later
            in the installation process, using the StorageGRID installation GUI.''')

    # port-configuration, VLAN IDs and bond mode settings became available in 1.7
    if version < (1, 7) and (args.port_configuration or args.grid_bond_mode or args.client_bond_mode or
                             args.grid_vlan_id or args.client_vlan_id):
        raise DataInconsistencyError(
            '''The firmware on this appliance does not include support for
            changing port configuration or bond mode or setting VLAN ID. You must
            upgrade the StorageGRID installer to perform these operations.''')

    # Make network changes (these all affect the /networking API)
    if args.admin_ip or args.admin_cidr or args.client_cidr or args.grid_cidr:
        if args.admin_ip:
            # Tell the appliance where the PRIMARY-ADMIN-NODE-IP is
            log.info('Updating primary Admin Node (StorageGRID Installer) to ' + args.admin_ip)
            sga.call('POST', '/networking/submit/SGI', 'sgiIP=' + args.admin_ip)
        if args.grid_cidr:
            change_interface_ip_v1(args.grid_cidr, 'br0', networking)
        if args.admin_cidr:
            change_interface_ip_v1(args.admin_cidr, 'br1', networking)
        if args.client_cidr:
            change_interface_ip_v1(args.client_cidr, 'br2', networking)

        # Refresh the networking structure
        log.info('Requesting networking configuration')
        networking = json.loads(sga.call('GET', '/networking'))

    # These two lists are ordered in the corresponding order of the devices "global" (br1, br0, br2)
    del_route_devices = [args.del_admin_route, args.del_grid_route, args.del_client_route]
    add_route_devices = [args.add_admin_route, args.add_grid_route, args.add_client_route]

    # Make routing deletions
    routes = None
    for i, del_route_device in enumerate(del_route_devices):
        if del_route_device:
            # We only need to grab the routes once for all the deletes
            if not routes:
                routes, default_route = get_routes()
            del_routes(del_route_device, devices[i], routes)

    # Make routing additions
    routes = None
    for i, add_route_device in enumerate(add_route_devices):
        if add_route_device:
            # We only need to grab the routes once for all the additions
            if not routes:
                routes, default_route = get_routes()
            add_routes(add_route_device, devices[i], networking['config'], default_route)

    # Set node name
    if args.node_name:
        set_node_name(args.node_name)

    if args.forceConfig_flag:
        if version < (1, 5):
            if args.forceConfig_flag == 'false':
                raise DataInconsistencyError('The firmware on this appliance does not support ' +
                                             'preserving existing user data across a reinstall.  If this is ' +
                                             'an initial install, or you want to delete all existing data on ' +
                                             'this appliance, use --forceConfig-flag true.')
        else:
            if args.forceConfig_flag == 'true':
                resp = sga.call('POST', '/sys/setFlag/forceConfig')
                print_hashed(['Reformatting of all attached storage will',
                              'be performed on this appliance.', '',
                              'Reformatting will cause loss of all data.'])
            else:
                resp = sga.call('POST', '/sys/setFlag/autoConfig')
                print_hashed(['Reformatting of all attached storage will not be performed on',
                              'this appliance. Existing data will be preserved.'])

    if args.client_network_state:
        set_client_network_state(networking, args.client_network_state, args.client_vlan_id)

    if args.port_configuration or \
            args.grid_bond_mode or \
            args.client_bond_mode or \
            args.grid_vlan_id or \
            args.client_vlan_id:
        configure_ports(networking, args.port_configuration, args.grid_bond_mode, args.client_bond_mode,
                        args.grid_vlan_id, args.client_vlan_id)

    return(networking)


def change_interface_ip_v2(address, dev):
    '''Update the address of a particular interface (dev).'''

    global networks
    global sga

    put_data = {}
    if address == 'DHCP':
        put_data['useDhcp'] = True
    else:
        put_data['useDhcp'] = False
        put_data['cidr'] = address
        ip = address.split('/')[0]

    timeout = None
    if 'cidr' in networks['interfaces'][dev] and sga.ip == str(networks['interfaces'][dev]['cidr']).split('/')[0]:
        timeout = 1
        if not args.ignore_warnings:
            raise DataInconsistencyWarning('Cannot change the "' + DEV[dev]['display'] +
                                           '" IP because you are using it.\n' +
                                           '  Use --ignore-warnings to override (connectivity will be lost).')
    log.info('Updating address of the ' + DEV[dev]['display'] + ' to ' + address + '.')
    try:
        # If we're changing our own IP, timeout will be 1
        sga.call('PUT', '/networks/' + dev, put_data, timeout)
    except socket.timeout:
        pass

    # If the user just changed the IP being used for communication, update the sga object
    if 'cidr' in networks['interfaces'][dev] and sga.ip == str(networks['interfaces'][dev]['cidr']).split('/')[0]:

        if address == 'DHCP':
            raise DataInconsistencyError(DEV[dev]['display'] + 'interface changed to DHCP.\n' +
                                         '  Use its new address to continue using this script.')
        else:
            # Update the IP of the sga object
            sga.update_ip(ip)
            log.info('Connecting to ' + sga.base_url + ' (Checking connectivity with new IP)')
            try:
                # Test the connection... Do nothing with the data
                sga.call('GET', '/system-info')
            except SgaInstaller.ResponseError as e:
                if str(e) == '404':
                    pass
    else:
        if address == 'DHCP':
            log.info('Waiting for interface to acquire DHCP address.')
            networks['interfaces'][dev]['cidr'] = None
            tries = 0
            while networks['interfaces'][dev]['cidr'] is None and tries < 3:
                networks = json.loads(sga.call('GET', '/networks'))['data']
                tries += 1
                sleep(args.poll_time)

            if networks['interfaces'][dev]['cidr'] is None:
                raise DataInconsistencyError('The ' + DEV[dev]['display'] + ' did not get a DHCP address.')


def change_interface_ip_v1(address, dev, networking):
    '''Update the IP and Mask of a particular interface (dev).'''

    global sga

    if address == 'DHCP':
        # DHCP introduced in versions 1.5
        if version < (1, 5):
            raise DataInconsistencyError('This appliance does not support DHCP.')
        endpoint = 'setDHCP'
        post_data = 'interface=' + dev + '\nflag=force'
    else:
        ip, bits = address.split('/')
        mask = cidr_to_netmask(bits)
        endpoint = DEV[dev]['api']
        post_data = 'address=' + ip + '\nnetmask=' + mask + '\nflag=force'

    timeout = None

    if sga.ip == networking['config'][dev]['ip']:
        timeout = 1
        if not args.ignore_warnings:
            raise DataInconsistencyWarning('Cannot change the "' + DEV[dev]['display'] +
                                           '" IP because you are using it.\n' +
                                           '  Use --ignore-warnings to override (connectivity will be lost).')
    log.info('Updating address of the ' + DEV[dev]['display'] + ' to ' + address + '.')
    try:
        # If we're changing our own IP, timeout will be 1
        sga.call('POST', '/networking/submit/' + endpoint, post_data, timeout)
    except socket.timeout:
        pass

    # If the user just changed the IP being used for communication, update the sga object
    if sga.ip == networking['config'][dev]['ip']:

        if address == 'DHCP':
            raise DataInconsistencyError(DEV[dev]['display'] + 'interface changed to DHCP.\n' +
                                         '  Use its new address to continue using this script.')
        else:
            # Update the IP of the sga object
            sga.update_ip(ip)
            log.info('Connecting to ' + sga.base_url + ' (Checking connectivity with new IP)')
            try:
                # Test the connection... Do nothing with the data
                sga.call('GET', '/sys/pgeVersion')
            except SgaInstaller.ResponseError as e:
                if str(e) == '404':
                    pass
            except:
                raise
    else:
        if address == 'DHCP':
            log.info('Waiting for interface to acquire DHCP address.')
            networking['config'][dev]['ip'] = '0.0.0.0'
            tries = 0
            while networking['config'][dev]['ip'] == '0.0.0.0' and tries < 3:
                networking = json.loads(sga.call('GET', '/networking'))
                tries += 1
                sleep(args.poll_time)

            if networking['config'][dev]['ip'] == '0.0.0.0':
                raise DataInconsistencyError('Interface (' + DEV[dev]['display'] + ') did not get a DHCP address.')


def set_gateway(gateway, dev):
    '''Set the gateway of a particular interface.'''
    log.info('Setting gateway "' + gateway + '" for ' + DEV[dev]['display'] + '.')
    sga.call('PUT', '/networks/' + dev + '/routing/gateway', {'gateway': gateway})


def add_subnets(subnets, dev):
    '''Add subnets to a particular interface.'''
    log.info('Adding subnets "' + ' ,'.join(subnets) + '" to ' + DEV[dev]['display'] + '.')
    sga.call('POST', '/networks/' + dev + '/routing/subnets', {'subnets': subnets})


def del_subnets(subnets, dev):
    '''Delete list of subnets from a particular interface.'''
    log.info('Deleting subnets ' + ', '.join(subnets) + ' from ' + DEV[dev]['display'] + '.')
    sga.call('DELETE', '/networks/' + dev + '/routing/subnets', {'subnets': subnets})


def add_routes(add_routes, dev, config, default_route):
    '''Add a route associated with a particular interface.'''
    # Check that the interface is configured
    if config[dev]['ip'] == '0.0.0.0' and config[dev]['netmask'] == '0.0.0.0':
        raise DataInconsistencyError('Can not add routes to "' +
                                     DEV[dev]['display'] + '", as it is not configured.')

    for add_route in add_routes:
        log.info('Adding route "' + add_route + '" to ' + DEV[dev]['display'] + '.')

        # The " via " pattern was already validated when arguments were parsed
        address, gateway = add_route.split(' via ')
        address = re.sub(r'^default$', '0.0.0.0/0', address)

        if address == '0.0.0.0/0' and default_route:
            raise DataInconsistencyError('Can not add default route "' + add_route + '" as it already ' +
                                         'exists on "' + DEV[default_route['dev']]['display'] + '".')

        # Validate the gateway is in the range of the interface's network mask
        dev_cidr_address = config[dev]['ip'] + '/' + netmask_to_cidr(config[dev]['netmask'])
        network = IPv4(str(dev_cidr_address), 'CIDR')
        if not network.ip_in_network(IPv4(gateway)):
            raise DataInconsistencyError('Can not add route "' + add_route + '" to ' + DEV[dev]['display'] + '.\n'
                                         '  IP (' + gateway + ') is not in the "' + DEV[dev]['display'] +
                                         '" range (' + network.get_network_string() + ').')

        sga.call('POST', '/networking/routes/add', str('interface=' + dev +
                                                       '\ngateway=' + gateway +
                                                       '\ndestination=' + address))


def del_routes(del_routes, dev, routes):
    '''Delete a route associated with a particular interface.'''
    for del_route in del_routes:
        route_found = False
        del_route = re.sub(r'^0.0.0.0/0 ', 'default ', del_route)
        for route in routes:
            if route['display'] == del_route and route['dev'] == dev:
                route_found = True
                log.info('Deleting route "' + del_route + '" from ' + DEV[dev]['display'] + '.')
                sga.call('POST', '/networking/routes/delete', 'route=' + route['route'])
                break
        if not route_found:
            raise DataInconsistencyError('Could not delete route "' + del_route + '" from ' +
                                         DEV[dev]['display'] + ', not found.')


def get_routes():
    '''Fetch all the routes in the system and parse into a structure.'''

    routes = []
    default_route = None

    log.info('Requesting routes configuration')
    sga_routes = json.loads(sga.call('GET', '/networking/routes'))

    # Remove the "proto kernel" and "default" routes (we don't need to display them)
    sga_routes = [x for x in sga_routes if not re.search(r'(proto kernel)', x)]

    # Iterate over the devices
    for dev in devices:
        # Iterate over the filtered routes that match the current device
        for route in filter(lambda x: re.search(r' dev ' + dev + ' *$', x), sga_routes):
            if sys.version_info < (3, 0):
                route = route.strip().encode('utf-8')
            else:
                route = route.strip()

            # If the route has a 32 bit mask, it does not implicitly show "/32"
            match = re.match(r'^(\d+.\d+.\d+.\d+)((?:/)\d+)? via (\d+.\d+.\d+.\d+) dev ' + dev + ' *$', route)
            if match and not match.group(2):
                display = match.group(1) + '/32 via ' + match.group(3)
            else:
                display = re.sub(r' dev ' + dev + ' *$', '', route)

            # Create a more manageable structure
            routes.append({'display': display,
                           'dev': dev,
                           'route': route})
            # Find the default route
            if re.match('^default ', routes[-1]['route']):
                default_route = routes[-1]
    return(routes, default_route)


def set_system_config(node_name, raid_mode):
    '''Set the StorageGRID node name for this appliance.'''

    # system_config was populated prior to calling this function
    # Update the changed values and PUT
    if node_name:
        system_config['name'] = node_name
    if raid_mode:
        system_config['raidMode'] = raid_mode

    sga.call('PUT', '/system-config', system_config)


def set_node_name(node_name):
    '''Set the StorageGRID node name for this appliance.'''

    sga.call('POST', '/networking/submit/nodename', 'nodename=' + node_name)


def set_client_network_state(networking, state, vlanid):
    '''Set the state of the client network to enabled or disabled.'''

    global sga
    timeout = None

    if sga.ip == networking['config']['br2']['ip']:
        timeout = 1
        if not args.ignore_warnings and state == 'disabled':
            raise DataInconsistencyWarning('Cannot disable the "' + DEV['br2']['display'] +
                                           '" because you are using it.\n' +
                                           '  Use --ignore-warnings to override (connectivity will be lost).')
    log.info('Setting the state of ' + DEV['br2']['display'] + ' to ' + state + '.')

    post_data = 'interface=br2\nflag=force\nstate=' + state
    if vlanid:
        post_data += '\nvlanid=' + vlanid

    try:
        # If we're disabling our own network, timeout will be 1
        sga.call('POST', '/networking/submit/setInterfaceState', post_data, timeout)
    except socket.timeout:
        pass

    if state == 'enabled':
        log.info('Waiting for ' + DEV['br2']['display'] + ' to acquire DHCP address.')
        networking['config']['br2']['ip'] = '0.0.0.0'
        tries = 0
        while networking['config']['br2']['ip'] == '0.0.0.0' and tries < 6:
            networking = json.loads(sga.call('GET', '/networking'))
            tries += 1
            sleep(args.poll_time)

        if networking['config']['br2']['ip'] == '0.0.0.0':
            raise DataInconsistencyError('Interface (%s) did not get a DHCP address.' % DEV['br2']['display'])


def wait_for_dhcp_v2(dev, abort=True):

    global networks

    # Wait if the interface is set for DHCP and the state is not acquired
    if networks['interfaces'][dev]['useDhcp'] and networks['interfaces'][dev]['dhcpState'] != 'acquired':
        log.info('Waiting for ' + DEV[dev]['display'] + ' to acquire DHCP address.')
        tries = 0
        while networks['interfaces'][dev]['dhcpState'] != 'acquired' and tries < 6:
            networks = json.loads(sga.call('GET', '/networks'))['data']
            tries += 1
            sleep(args.poll_time)

        if networks['interfaces'][dev]['dhcpState'] != 'acquired':
            if abort:
                if args.ignore_warnings:
                    print_hashed(['Warning: The ' + DEV[dev]['display'] + ' did not get a DHCP address.',
                                 '*** Above warnings ignored (--ignore-warnings was specified). ***'])
                else:
                    raise DataInconsistencyError('The ' + DEV[dev]['display'] + ' did not get a DHCP address.' +
                                                 '\n  Use --ignore-warnings to override.')
            else:
                print_hashed(['The ' + DEV[dev]['display'] + ' did not get a DHCP address.'])


def wait_for_dhcp_v1(networking, iface):
    if networking['config'][iface]['type'] != 'static':
        log.info('Waiting for ' + DEV[iface]['display'] + ' to acquire DHCP address.')
        networking['config'][iface]['ip'] = '0.0.0.0'
        tries = 0
        while networking['config'][iface]['ip'] == '0.0.0.0' and tries < 6:
            networking = json.loads(sga.call('GET', '/networking'))
            tries += 1
            sleep(args.poll_time)

        if networking['config'][iface]['ip'] == '0.0.0.0':
            raise DataInconsistencyError('Interface (' + DEV[iface]['display'] + ') did not get a DHCP address.')


def update_link_config():
    '''Updating the link-config on this appliance.'''

    global link_config
    global sga

    # Update bond-mode, vlan-id and/or state of grid, admin and/or client
    for dev in devices:
        # Parse network-state, bond-mode and vlan-id options corresponding to this device
        state = vars(args).get(dev + '_network_state')
        bond_mode = vars(args).get(dev + '_bond_mode')
        vlan_id = vars(args).get(dev + '_vlan_id')
        device = DEV[dev]['display']
        # Check if the device is enabled (device entry is present)
        if networks['interfaces'].get(dev):
            # Check if we're modifying the device we're usung
            if networks['interfaces'][dev].get('cidr') and sga.ip == str(networks['interfaces'][dev]['cidr']).split('/')[0] and \
                    (state or bond_mode or vlan_id):
                if not args.ignore_warnings:
                    raise DataInconsistencyWarning('The connection might be lost if you you modify the configuration of the ' +
                                                   device + ' being used to connect to the appliance. Connectivity ' +
                                                   'will not be restored until switch changes take effect\n' +
                                                   '  Use --ignore-warnings to override (connectivity may be lost).')

        # Updating the state
        if state:
            enabled_flag = True if state == 'enabled' else False
            log.info('Setting the state of ' + device + ' to ' + state + '.')
            # Just update the link_config structure (there will be a post to to it below)
            link_config['interfaces'][dev]['enabled'] = enabled_flag
        # Update the bond-mode
        if bond_mode:
            log.info('Setting the bond mode of ' + device + ' to ' + bond_mode + '.')
            # Just update the link_config structure (there will be a post to to it below)
            link_config['interfaces'][dev]['bondMode'] = bond_mode
        # Update the vlan-id
        if vlan_id:
            log.info('Setting the vlanid of ' + device + ' to ' + vlan_id + '.')
            vlan_id_value = vlan_id if vlan_id != 'novlan' else None
            # Just update the link_config structure (there will be a post to to it below)
            link_config['interfaces'][dev]['vlanid'] = vlan_id_value

    if args.port_configuration:
        log.info('Setting the port configuration mode to ' + args.port_configuration + '.')
        link_config['portGrouping'] = args.port_configuration

    if args.link_speed:
        log.info('Setting the port link speed to ' + args.link_speed + '.')
        link_config['linkSpeed'] = args.link_speed

    try:
        # If we're modifying our own network (or global link changes), timeout will be 30
        sga.call('PUT', '/link-config', link_config, 30)
    except socket.timeout:
        log.error('Unable to communicate with the appliance via ' + sga.ip + '.')
        log.info('Delaying 30 seconds before continuing.')
        sleep(30)


def configure_ports(networking, portcfg, gridbondmode, clientbondmode, gridvlanid, clientvlanid):
    '''Configuring the ports on this appliance.'''

    global sga
    timeout = None

    if sga.ip == networking['config']['br0']['ip'] or sga.ip == networking['config']['br2']['ip']:
        timeout = 10
        if not args.ignore_warnings:
            raise DataInconsistencyWarning('The connection might be lost if you you modify the configuration of the ' +
                                           '10GbE ports used to connect to the appliance. Connectivity will not be restored ' +
                                           'until switch changes take effect.\n' +
                                           '  Use --ignore-warnings to override (connectivity may be lost).')
    params = dict()
    params['portcfg'] = networking['config']['portcfg']
    if portcfg:
        log.info('Setting the port configuration mode to ' + portcfg + '.')
        params['portcfg'] = portcfg
    else:
        params['portcfg'] = networking['config']['portcfg']
    if gridbondmode:
        log.info('Setting the bond mode of ' + DEV['br0']['display'] + ' to ' + gridbondmode + '.')
        params['gridbondmode'] = gridbondmode
    else:
        params['gridbondmode'] = networking['config']['br0']['bondmode']
    if clientbondmode:
        log.info('Setting the bond mode of ' + DEV['br2']['display'] + ' to ' + clientbondmode + '.')
        params['clientbondmode'] = clientbondmode
    else:
        params['clientbondmode'] = networking['config']['br2']['bondmode']
    if gridvlanid:
        log.info('Setting the VLAN ID of ' + DEV['br0']['display'] + ' to ' + gridvlanid + '.')
        params['gridvlanid'] = gridvlanid
    else:
        params['gridvlanid'] = networking['config']['br0']['vlan']
    if clientvlanid:
        log.info('Setting the VLAN ID of ' + DEV['br2']['display'] + ' to ' + clientvlanid + '.')
        params['clientvlanid'] = clientvlanid
    else:
        params['clientvlanid'] = networking['config']['br2']['vlan']

    # Set timeout as there is a possibility of losing access to appliance
    sga.call('POST', '/networking/submit/portConfig', params, timeout)

    wait_for_dhcp_v1(networking, 'br0')
    wait_for_dhcp_v1(networking, 'br2')


def wait_for_primary_admin_v2(timeout, abort=True):
    '''Check "/admin-connection" until PA is ready.'''

    global admin_connection

    sga.quiet = True
    detail_message = None
    last_detail_message = None
    already_connected = True
    # Get the epoch time, add the timeout
    epoch_timeout = time() + timeout
    log.info('Verifying connectivity to primary Admin Node: ')
    if admin_connection['connectionState'] != 'ready':
        log.info('Appliance cannot communicate with the primary Admin Node IP:' +
                 str(admin_connection['ip']) + '.', False)

    # While the Primary Admin Node is not ready, wait for it
    while admin_connection['connectionState'] != 'ready':
        already_connected = False
        detail_message = admin_connection.get('detailMessage')
        if detail_message == last_detail_message:
            log.info('.', False)
        else:
            if detail_message:
                log.info('\n    Message from appliance: ' + detail_message, False)

        if time() >= epoch_timeout:
            # Print a LF (and a corresponding message)
            log.info(' Failed')
            if abort:
                raise ApplianceTimeoutError('Timed out waiting for primary Admin Node.')
            else:
                break
        else:
            sleep(args.poll_time)
            # refresh the /admin-connection state
            admin_connection = json.loads(sga.call('GET', '/admin-connection'))['data']
            last_detail_message = detail_message

    if admin_connection['connectionState'] == 'ready' and not already_connected:
        # Print a LF (and a corresponding message)
        log.info(' Connected')

    sga.quiet = False


def wait_for_primary_admin_v1():
    '''Perform GET "/networking" check the status json, wait until SGI is reachable.'''

    waiting = True
    sga.quiet = True
    # Get the epoch time, add the timeout
    epoch_timeout = time() + install_args.timeout * 60
    while waiting:
        # Perform a GET on "/networking"... Retreives status of the install
        config = json.loads(sga.call('GET', '/networking'))

        # If the "status/sgi/ok" field is true,
        # the Primary Admin Node is up and accessible to the appliance
        if config['status']['sgi']['ok']:
            waiting = False
        # The "status/sgi/ok" field is false, display the message
        else:
            log.info('Appliance cannot communicate with the primary Admin Node IP:' +
                     config['status']['sgi']['IP'] + '.')
            log.info('    Message from appliance: ' + config['status']['sgi']['message'])
            if time() >= epoch_timeout:
                raise ApplianceTimeoutError('Timed out waiting for primary Admin Node.')
            sleep(args.poll_time)

    sga.quiet = False


def monitor_install_v2():
    '''Monitor the progress of the installation.'''

    global install_status

    log.info('Monitoring installation progress')

    # This will summarize until finished monitoring
    install_summary_polling()
    log.info('')

    # install_status was updated within the polling (check if we failed)
    if install_status['failed']:
        # This call does not return
        install_status_errors('/install-status API returned "failed" status')

    # Check if we completed
    elif install_status['complete']:
        storagegrid_joined_message()

    # Not failed, not complete (node needs to be approved)
    else:
        storagegrid_monitor_message()


def install_summary_polling():
    '''Print the install summary while polling for updates'''

    global install_status

    stage_printed = []
    step_completed = []
    last_logline = ''
    sga.quiet = True

    print_hashed(['Polling /api/v2/install-status for installation progress.',
                  'Calls to the API are silenced during polling.'])

    # Stay in this loop forever (logic in the block to break out)
    while True:
        # Update width (in case terminal is resized)
        try:
            width = int(subprocess.check_output(['stty', 'size'], stderr=subprocess.STDOUT).split()[1])
        except(ValueError, IndexError, subprocess.CalledProcessError):
            # Width 0 will print the full line without padding
            width = 0

        for stage in install_status['status']:
            # Do not process pending stages
            if stage['state'] == 'pending':
                break

            # Only print stages which haven't been printed
            if stage['name'] not in stage_printed:
                log.info('\n  Stage: ' + stage['name'])
                log.info('    ' + 'Step'.ljust(31) + 'Progress'.ljust(22) + 'Status')
                log.info('    ' + ('-' * 29).ljust(31) + ('-' * 20).ljust(22) + ('-' * 20).ljust(22))
                stage_printed.append(stage['name'])

            for step in stage['steps']:
                # Only these states get printed ('complete', 'skipped', 'running')
                if step['state'] != 'pending' and step['name'] not in step_completed:
                    # Add step-name to the line
                    line = '    ' + step['name'].ljust(31)
                    if step['state'] == 'running':
                        # Add progress
                        line += (int(step['progress'] / 5 + 0.5) * '*').ljust(22)
                        # Add the message to the end
                        if step['message'] is not None:
                            line += step['message'].ljust(33)
                        else:
                            line += "Unknown".ljust(33)
                        if width:
                            if width >= len(line):
                                # Pad line with spaces to EOL
                                line += ' ' * (width - len(line))
                            else:
                                line = line[:width]
                        # If the step hit 100% tag as complete
                        if step['progress'] == 100:
                            line += '\n'
                            # Tag this step as complete (so it will not be updated again)
                            step_completed.append(step['name'])
                        else:
                            line += '\r'

                    else:
                        # Add progress (100%)
                        line += (20 * '*').ljust(22)
                        # Not running (no message), add state
                        line += step['state'].ljust(33)
                        if width:
                            if width >= len(line):
                                # Pad line with spaces to EOL
                                line += ' ' * (width - len(line))
                            else:
                                line = line[:width]
                        line += '\n'
                        # Tag this step as complete (so it will not be updated again)
                        step_completed.append(step['name'])

                    # Print the line we just built up
                    log.info(line, False)

                # If we just processed a running step, skip the rest
                if step['state'] == 'running':
                    break
            # If we just processed a running stage, skip the rest
            if stage['state'] == 'running':
                break

        # See if any logLines have shown up
        if len(install_status['logLines']) > 1:

            # Persistent variable to detect if this has been called before
            # Basically do this block once
            if not hasattr(install_summary_polling, 'already_printed'):
                install_summary_polling.already_printed = True

                log.info('')
                storagegrid_installed_message()

                # See if we monitor to the end
                if monitor_args.monitor_storagegrid_install:
                    # Remove the last printed stage and step so they reprint
                    stage_printed.pop()
                    step_completed.pop()
                    # We have not printed the discovered logLines
                    # Allow the message to be viewed for a moment
                    sleep(args.poll_time)
                    # Reexecute the print logic for stage and step
                    continue

            # See if we monitor to the end
            if monitor_args.monitor_storagegrid_install:
                log_lines = install_status['logLines']
                try:
                    start_index = log_lines.index(last_logline) + 1
                except ValueError:
                    start_index = 0
                last_logline = log_lines[-1]
                log_lines = log_lines[start_index:]
                if log_lines:
                    log.info('      ---------- Log output from Installer VM (last ' +
                             str(len(log_lines)) + ' lines) ----------')
                    for line in log_lines:
                        log.info('        ' + line)

            # Not monitoring until the end, so we exit
            else:
                break

        # Check for exit conditions status which just printed (this way failed states get printed)
        if not install_status['started'] or install_status['complete'] or install_status['failed']:
            break

        # Wait for polling time and get a fresh install-status
        sleep(args.poll_time)
        install_status = json.loads(sga.call('GET', '/install-status'))['data']

    sga.quiet = False


def install_status_errors(default_msg):
    ''''Find errors in each of the stage structurs'''

    errors = []
    # Collect the errors
    for stage in install_status['status']:
        for error in stage['errors']:
            errors.append('Stage: ' + stage['name'] + ': Error: ' + error)
        for step in stage['steps']:
            if step['state'] == 'failed':
                errors.append('Step: ' + step['name'] + ': Error: ' + step['message'])

    if errors:
        raise ApplianceInstallationError('\n'.join(errors))
    else:
        raise ApplianceInstallationError(default_msg)


def monitor_install_v1():
    '''Monitor the progress of the installation.'''

    last_flat_status = False
    sg_started_msg_flag = False
    sg_finished_flag = False
    log.info('Monitoring installation progress')
    while True:
        flat_status = flatten_status(json.loads(sga.call('GET', '/provisioning/json')))

        # Get the "Install StorageGRID software" item
        sg_install = get_item('PostInstall_event', flat_status)
        if sg_install['State'] == 'Running':

            # Show this message only once
            if not sg_started_msg_flag:
                sg_started_msg_flag = True
                print_status_table(flat_status)
                storagegrid_installed_message()

            if monitor_args.monitor_storagegrid_install:
                # Go get and display some lines from the log
                lines = get_install_log_lines()

                if lines:
                    # Quiet down the sga calls so we only see the log output
                    sga.quiet = True

                for line in lines:
                    log.info('  ' + line)

            else:
                # It's "Running" and --monitor-storagegrid-install was not specified, we're done
                break
        else:
            # Allow sga calls to be seen again
            sga.quiet = False

            print_status_delta(flat_status, last_flat_status)

        # Get the "Boot into StorageGRID" item
        sg_boot = get_item('Chainload_event', flat_status)
        # If it's "Rebooting" we're done monitoring (remove trailing HTML first)
        if re.match('(Rebooting|Reboot initiated)', sg_boot['State'].split('<')[0]):
            sg_finished_flag = True
            break

        check_failed_items(flat_status)
        last_flat_status = flat_status

        sleep(args.poll_time)

    # If we were showing deltas, show one full table before we quit
    if monitor_args.monitor_delta:
        print_status_table(flat_status)

    if sg_finished_flag:
        storagegrid_joined_message()
    else:
        storagegrid_monitor_message()


def storagegrid_installed_message():
    '''Print a friendly message that the node can be approved now'''
    print_hashed(['StorageGRID software has been installed on the appliance.',
                  'Open your web browser and navigate to the primary Admin Node,',
                  'or execute the configure_storagegrid.py command, to approve',
                  'the addition of the appliance Storage Node to the grid.'])


def storagegrid_joined_message():
    '''Print a friendly message that the node joined the grid'''
    print_hashed(['This StorageGRID Appliance has successfully joined the grid.'])


def storagegrid_monitor_message():
    '''Print a friendly message for full monitoring'''
    print_hashed(['After the grid node is approved, you can monitor the',
                  'completion of the installation by running this script with',
                  '"monitor --monitor-storagegrid-install" sub-command and option.'])


def get_install_log_lines():
    '''Fetch some lines from the postinstall log and remove lines already reported.'''

    log_lines = []

    sga_quiet_state = sga.quiet
    sga.quiet = True
    # This is the only place the number of lines is specified
    response = sga.call('GET', '/logs/postinstall/tail/10')
    sga.quiet = sga_quiet_state

    if sga.status == 200:
        log_lines = json.loads(response)
        try:
            start_index = log_lines.index(get_install_log_lines.last_line) + 1
        except (AttributeError, ValueError):
            start_index = 0
        get_install_log_lines.last_line = log_lines[-1]
        log_lines = log_lines[start_index:]

    return(log_lines)


def pretty_print(s, num_spaces):
    '''Pretty print a json string'''
    s = json.dumps(s, indent=4)
    s = s.split('\n')
    s = [(num_spaces * ' ') + line for line in s]
    s = '\n'.join(s)
    return(s)


def flatten_status(status_struct, indent=''):
    '''Create a single-level structure from the muti-layer structure'''
    flat_status = []
    flat_status.append({'Name': status_struct['Name'],
                        'State': status_struct['State'],
                        'DisplayString': status_struct['DisplayString'],
                        'Cause': status_struct['Cause']})
    for child in status_struct['Children']:
        if child['DisplayString'] != '':
            child['DisplayString'] = '  ' + indent + child['DisplayString']
        flat_status.extend(flatten_status(child, indent + '  '))

    return(flat_status)


def get_item(name, flat_status):
    '''Find a specific item in the flattened structure using the name field'''
    for item in flat_status:
        if item['Name'] == name:
            return(item)


def check_failed_items(flat_status):
    '''Check all items in the flattened structure for "State: Failed" '''
    failed_items = []
    for item in flat_status:
        if item['State'] == 'Failed':
            failed_items.append(item)

    if failed_items:
        print_status_table(failed_items)
        raise DataInconsistencyError('Appliance installation has failed.\n' +
                                     '  Address issues, then use the "reboot" sub-command to get out of this state.')


def print_status_delta(status, last_status):
    '''Only print the status which changed between status and last_status'''

    if monitor_args.monitor_delta and last_status:
        delta_status = []
        for item in status:
            item_found = False
            for delta in last_status:
                # Find the item
                if item['Name'] == delta['Name']:
                    item_found = True
                    if item['State'] != delta['State']:
                        delta_status.append(item)
                        break
            if not item_found:
                delta_status.append(item)
        print_status_table(delta_status, False)
    else:
        print_status_table(status)


def print_status_table(status, full_output=True):
    '''Format the status structure for printing.'''

    table = []
    if full_output:
        table.append(['Item', 'State'])

    for item in status:
        if item['DisplayString'] != '':
            # Remove trailing HTML from State for printing
            table.append([item['DisplayString'], item['State'].split('<')[0]])
            if item['Cause']:
                table.append(['', '    Cause: ' + item['Cause']])

    print_table(table, full_output)


def print_table(table, full_output=True):
    '''Print a table; one line per item.
    full_output=True prints borders.
    full_output=False prints without borders.'''

    # Get the column with and create a list
    col_width = [max(len(str(x)) for x in col) for col in zip(*table)]

    left = '  '
    delim = '   '
    right = ''
    if full_output:
        left = '| '
        delim = ' | '
        right = ' |'
        # Print a separator above the header
        log.info('+-' + '-+-'.join(['-' * col_width[i] for i in range(len(col_width))]) + '-+')

    # Iterate over the table
    for j, line in enumerate(table):
        # Format and print a line
        # D-09614: workaround for line parsing error
        log.info(left + delim.join(str(x).ljust(col_width[i])
                                   for i, x in enumerate(line)) + right)
        # Is this the first line?
        if j == 0 and full_output:
            # Print a separator below the header
            log.info('+-' + '-+-'.join(['-' * col_width[i] for i in range(len(col_width))]) + '-+')

    if full_output:
        # Print a separator below the table
        log.info('+-' + '-+-'.join(['-' * col_width[i] for i in range(len(col_width))]) + '-+')


def print_hashed(msgs, justification='center'):
    '''Print a formatted column surrounded hashes'''

    # Get the column with and create a list
    width = max(len(x) for x in msgs) + 2

    log.info('#####' + '#' * width + '#####')

    # Iterate over the msgs
    for text in msgs:
        if justification == 'center':
            log.info('#####' + text.center(width) + '#####')
        elif justification == 'left':
            log.info('##### ' + text.ljust(width - 1) + '#####')
        else:
            raise Exception('Unsupported justification: ' + justification)

    log.info('#####' + '#' * width + '#####')


def cidr_to_netmask(cidr_postfix):
    '''Converts cidr postfix (eg. 24) of an address into a dotted quad netmask (eg. 255.255.255.0) for IPv4.'''
    cidr_postfix = int(cidr_postfix)
    if cidr_postfix == 32:
        return '255.255.255.255'
    val = 0
    # Generate a uint32 from the postfix
    for i in range(32):
        if i < cidr_postfix + 1:
            val = val + 1
        val = val << 1
    # Convert the uint32 to dotted quad
    out_str = ''
    for i in range(4):
        tmp = val % 256
        val = int(val / 256)
        out_str = str(tmp) + out_str
        if i != 3:
            out_str = '.' + out_str
    return out_str


def netmask_to_cidr(netmask):
    '''Converts dotted quad netmask (eg. 255.255.255.0) into a cidr postfix (eg. 24) for IPv4.'''
    binary_str = ''
    for octet in netmask.split('.'):
        binary_str += bin(int(octet))[2:].zfill(8)
    return str(len(binary_str.rstrip('0')))


def show_config_v2():
    '''Use all the global API calls to summarize configuration.'''

    # About this appliance
    log.info('')
    log.info('  StorageGRID Appliance')
    table = []
    table.append(['  Name:', system_config['name']])
    print_table(table, False)
    log.info('')

    # StorageGRID primary Admin Node section
    log.info('  StorageGRID primary Admin Node')
    discovered = ''
    if admin_connection['useDiscovery']:
        discovered = ' (discovered)'
    table = []
    table.append(['  IP:', str(admin_connection['ip']) + discovered])
    table.append(['  State:', admin_connection['connectionState']])
    table.append(['  Message:', admin_connection['detailMessage']])
    table.append(['  Version:', admin_connection['storagegridVersion']])
    if admin_connection['useDiscovery']:
        field_label = '  Discovered IPs:'
        for discovered_ip in admin_connection['discoveredAddresses']:
            table.append([field_label, discovered_ip])
            field_label = '                 '
    print_table(table, False)
    log.info('')

    # Bond and VLAN configuration section
    log.info('  Bond and VLAN configuration')
    table = []
    table.append(['  Port bond mode:', str(link_config['portGrouping']).upper()])
    if 'linkSpeed' in link_config:
        table.append(['  Link speed:', link_config['linkSpeed'].upper()])
        if len(link_config['supportedLinkSpeeds']) > 1:
            table.append(['  Supported speeds:', ' '.join(link_config['supportedLinkSpeeds'])])
    for dev in devices:
        if link_config['interfaces'][dev]['enabled']:
            table.append(['', ''])
            table.append(['      ' + DEV[dev]['display'] + ':', 'ENABLED'])
            table.append(['          Bonding mode:', link_config['interfaces'][dev]['bondMode']])
            if link_config['interfaces'][dev].get('vlanid'):
                table.append(['          VLAN:', str(link_config['interfaces'][dev].get('vlanid'))])
            else:
                table.append(['          VLAN:', 'novlan'])
        else:
            table.append(['', ''])
            table.append(['      ' + DEV[dev]['display'] + ':', 'DISABLED'])
    print_table(table, False)
    log.info('')

    # Section for each network (Admin Network, Grid Network, Client Network)
    for dev in devices:
        if not link_config['interfaces'][dev]['enabled']:
            continue
        table = []
        ip_type = ''
        log.info('  ' + DEV[dev]['display'])
        if networks['interfaces'][dev]['useDhcp']:
            ip_type = ' (DHCP - ' + networks['interfaces'][dev]['dhcpState'] + ')'
        else:
            ip_type = ' (Static)'
        table.append(['  CIDR:', str(networks['interfaces'][dev]['cidr']) + ip_type])
        if 'mac' in networks['interfaces'][dev]:
            table.append(['  MAC:', str(networks['interfaces'][dev]['mac']).upper()])
        if 'routing' in networks['interfaces'][dev]:
            table.append(['  Gateway:', networks['interfaces'][dev]['routing']['gateway']])
            if networks['interfaces'][dev]['routing'].get('subnets'):
                field_label = '  Subnets:'
                for subnet in networks['interfaces'][dev]['routing']['subnets']:
                    table.append([field_label, subnet])
                    field_label = ''
        print_table(table, False)
        log.info('')

    errors = []
    warnings = []
    if system_info.get('networkError'):
        errors.append('Error:  The network configuration has the following errors: ')
        for error in networks['errors']:
            errors.append('  * ' + error)
    if system_info.get('compatibilityError'):
        errors.append('Error:  The appliance has the following configuration incompatibilities: ')
        for error in admin_connection['compatibilityErrors']:
            errors.append('  * ' + error)
    if system_info.get('needsAttention'):
        warnings.append('Warning:  The appliance hardware needs attention.')
        warnings.append('  Use SANtricity System Manager to check and resolve the issue.')
    if errors:
        print_hashed(errors, 'left')
    if warnings:
        print_hashed(warnings, 'left')
    if errors:
        sys.exit(5)
    if warnings and not args.ignore_warnings:
        print_hashed(['Warnings exist on your appliance hardware.',
                      '  If you have reviewed the warnings, and want to continue, ',
                      '  use --ignore-warnings to override.'], 'left')
        sys.exit(5)


def show_config_v1():
    '''Use the /networking and /networking/routes output to summarize configuration.'''

    # Perform a GET on "/networking"... Retreives status of the install
    networking = json.loads(sga.call('GET', '/networking'))

    routes, default_route = get_routes()

    table = []
    log.info('')
    log.info('  StorageGRID primary Admin Node')
    table.append(['  IP:', networking['status']['sgi']['IP']])
    table.append(['  Message:', networking['status']['sgi']['message']])
    print_table(table, False)
    log.info('')

    if 'portcfg' in networking['config']:
        table = []
        table.append(['  Port Configuration:', networking['config']['portcfg'].upper()])
        print_table(table, False)
        log.info('')

    config = networking['config']
    for dev in devices:
        table = []
        ip_type = ''
        # DHCP introduced in versions 1.5
        if version >= (1, 5):
            if config[dev]['type'] == 'static':
                ip_type = ' (Static)'
            else:
                ip_type = ' (DHCP)'
        log.info('  ' + DEV[dev]['display'])
        # Saving network as CIDR back into config structure so it can be used to identify issues (below)
        config[dev]['cidr'] = str(config[dev]['ip'] + '/' + netmask_to_cidr(config[dev]['netmask']))
        table.append(['  IP/Mask:', config[dev]['cidr'] + ip_type])
        if 'bondmode' in config[dev]:
            table.append(['  Bond mode:', str(config[dev]['bondmode']).upper()])
        if 'vlan' in config[dev]:
            table.append(['  VLAN:', config[dev]['vlan']])
        if 'state' in config[dev] and dev == 'br2':
            table.append(['  State:', str(config[dev]['state']).upper()])
        for route in routes:
            if route['dev'] == dev:
                table.append(['  ' + DEV[dev]['route'], route['display']])
        print_table(table, False)
        log.info('')

    #
    # Collect all configuration issues
    #

    issues = []
    # Check that the Grid Network is being used
    if config['br0']['cidr'] == '0.0.0.0/0':
        issues += ['- The (' + DEV['br0']['display'] + ') needs to be defined for StorageGRID to',
                   '  interact with this appliance.', '']

    # See if the interfaces have overlapping network definitions
    for i, dev1 in enumerate(devices):
        for dev2 in devices[i + 1:]:
            cidr1 = IPv4(config[dev1]['cidr'], 'CIDR')
            cidr2 = IPv4(config[dev2]['cidr'], 'CIDR')
            if cidr1.string != '0.0.0.0/0' and cidr2.string != '0.0.0.0/0':
                if cidr1.check_overlap(cidr2):
                    issues += ['- The "' + DEV[dev1]['display'] + '" (' + cidr1.string + ') subnet overlaps with',
                               '  the "' + DEV[dev2]['display'] + '" (' + cidr2.string + ') subnet.',
                               '  Interface subnetworks must not overlap.', '']

    # Assert that the default route exists on the "Grid Network" (if it exists)
    if default_route:
        if default_route['dev'] != 'br0':
            issues += ['- The default route "' + default_route['display'] + '" currently resides',
                       '  on the "' + DEV[default_route['dev']]['display'] + '" interface.',
                       '  It needs to reside on the "' + DEV['br0']['display'] + '" interface.', '']
    else:
        issues += ['- A default route does not exist on the ' + DEV['br0']['display'] + ' interface.',
                   '  Suggestion: Add the following route to the "' + DEV['br0']['display'] + '" interface:',
                   '        "default via <gateway>".', '']

    # Check route gateways under each interface
    for dev in devices:
        gateways = []
        for route in routes:
            if route['dev'] == dev:
                gateway_entry = route['display'].split(' via ')[1]
                if gateway_entry not in gateways:
                    gateways.append(gateway_entry)
        if len(gateways) > 1:
            issues += ['- ' + DEV[dev]['display'] + ' routes have more than one gateway:']
            for gateway in gateways:
                issues += ['    ' + gateway]
            issues += ['  Update "' + DEV[dev]['display'] + '" routes to use a single gateway.', '']
        elif dev == 'br2' and len(gateways) == 0 and config[dev]['cidr'] != '0.0.0.0/0':
            issues += ['- A route with a gateway does not exist on the ' + DEV[dev]['display'] + ' interface.',
                       '  Suggestion: Add the following route to the "' + DEV[dev]['display'] + '" interface:',
                       '        "1.1.1.1/32 via <gateway>".', '',
                       '        During StorageGRID software installation, the "default" gateway',
                       '  will be removed from the ' + DEV['br0']['display'] + ' and a new default gateway will',
                       '  be added to the ' + DEV[dev]['display'] + ' interface. Configuring the proposed',
                       '  suggestion creates a placeholder route having the <gateway> IP which',
                       '  will be used when the StorageGRID installation creates the route on the',
                       '  ' + DEV['br0']['display'] + '.', '']

    # Report the issues
    if issues:
        install_status = networking['status']['install']['status']
        if args.ignore_warnings:
            issues.append('*** Above warnings ignored (--ignore-warnings was specified). ***')
            print_hashed(issues, 'left')
        elif install_status == 'started':
            issues.append('*** Above warnings in the configuration. Installation in progress. ***')
            print_hashed(issues, 'left')
        else:
            issues.append('*** In order to continue, you must fix the above warnings. ***')
            print_hashed(issues, 'left')
            raise DataInconsistencyWarning('Issues exist in your StorageGRID configuration.\n' +
                                           '  If you have reviewed the warnings, and want to continue, ' +
                                           'use --ignore-warnings to override.')


class IPv4:

    def __init__(self, var, varType='IP'):
        if varType not in ['IP', 'CIDR', 'NETWORK']:
            raise DataInconsistencyError('Invalid varType: ' + varType)
        assert type(var) == str, 'IP address must be of type str not ' + str(type(var)) + '.'
        self.string = var
        match = re.match('^(\d+).(\d+).(\d+).(\d+)((?:/)\d+)?$', var)
        if not match:
            raise DataInconsistencyError(varType + ' (' + var + ') is not a valid IPv4 format.')
        if varType == 'IP' and match.group(5):
            raise DataInconsistencyError(varType + ' (' + var + ') cannot contain a network mask (' + match.group(5) + ').')
        if varType != 'IP' and not match.group(5):
            raise DataInconsistencyError(varType + ' (' + var + ') must contain network mask bits (e.g. "/24" after IP).')
        self.ip = (int(match.group(1)), int(match.group(2)), int(match.group(3)), int(match.group(4)))
        allZero = True
        bcast = True
        for octet in self.ip:
            if octet < 0 or octet > 255:
                raise DataInconsistencyError(varType + ' (' + var + ') is not a valid IPv4 format.')
            if octet > 0:
                allZero = False
                if octet != 255:
                    bcast = False
        self.ipInt = (self.ip[0] << 24) + (self.ip[1] << 16) + (self.ip[2] << 8) + self.ip[3]
        if match.group(5):
            self.mask = int(match.group(5)[1:])
            if self.mask < 0:
                raise DataInconsistencyError(varType + ' (' + var + ') negative mask is invalid.')
            if self.mask > 32:
                raise DataInconsistencyError(varType + ' (' + var + ') mask value (' + str(self.mask) + ') too high.')
            self.maskInt = 0xFFFFFFFF >> (32 - self.mask) << (32 - self.mask)
            if varType != 'CIDR' and ((self.ipInt << self.mask) & 0xFFFFFFFF) != 0:
                raise DataInconsistencyError(varType + ' (' + var + ') mask bits = ' + str(self.mask) +
                                             '\n  Network\'s mask must have zeros for all non-masked bits.')

    def min_int_ip(self):
        return(self.ipInt & self.maskInt)

    def max_int_ip(self):
        return(self.ipInt | (self.maskInt ^ 0xFFFFFFFF))

    def ip_in_network(self, ip):
        return(ip.ipInt <= self.max_int_ip() and ip.ipInt >= self.min_int_ip())

    def get_network_string(self):
        return(str((self.min_int_ip() & 0xFF000000) >> 24) + '.' +
               str((self.min_int_ip() & 0xFF0000) >> 16) + '.' +
               str((self.min_int_ip() & 0xFF00) >> 8) + '.' +
               str(self.min_int_ip() & 0xFF) + '/' + str(self.mask))

    def check_overlap(self, network):
        if self.min_int_ip() < network.min_int_ip():
            status = self.max_int_ip() > network.min_int_ip()
        elif network.min_int_ip() < self.min_int_ip():
            status = network.max_int_ip() > self.min_int_ip()
        else:
            status = True
        return(status)


class SgaInstaller:
    '''StorageGRID Appliance Installer class definition.'''

    class ResponseError(Exception):
        '''Raise a custom response error for non 200-299 results.'''

        def __init__(self, *args, **kwargs):
            Exception.__init__(self, *args, **kwargs)

    class ConfigError(Exception):
        '''Raise a custom response error for 422 (validation) results.'''

        def __init__(self, *args, **kwargs):
            Exception.__init__(self, *args, **kwargs)

    quiet = False

    def __init__(self, ip, verbose=False):
        '''Initialize http configuration.'''

        self.secure = True
        self.verbose = verbose
        self.base_uri = '/api'
        self.ctype = 'application/json'
        self.update_ip(ip)


    def call(self, method, uri, body=None, timeout=None):
        '''Call the StorageGRID Appliance installation API.
        Returns the response body.'''

        full_uri = self.base_uri + uri
        request = urllib_request.Request(self.base_url + full_uri)
        if method == 'POST' and not body:
            body = ''
        if isinstance(body, str):
            request.data = body.encode('utf-8')
            ctype = 'text/plain'
        elif body:
            request.data = json.dumps(body).encode('utf-8')
            ctype = 'application/json'
        else:
            ctype = self.ctype

        request.get_method = lambda: method
        request.add_header('Accept', 'application/json, application/xml, text/*')
        request.add_header('Content-Type', ctype + '; charset=UTF-8')
        time_string = strftime('%Y/%m/%d %H:%M:%S: ', localtime())
        if self.verbose or not self.quiet:
            # Informational output
            log.info(time_string + 'Performing ' + method + ' on ' + full_uri + '... ', False)
        else:
            log.quiet(time_string + 'Performing ' + method + ' on ' + full_uri + '... ')

        try:
            resp = self.opener.open(request, timeout=timeout)
        except urllib_error.HTTPError as e:
            resp = e
        except socket.timeout as e:
            log.error('Connection dropped')
            # Debug output
            log.debug('    Request: ' + method + ' ' + self.base_url + full_uri)
            if body:
                log.debug(pretty_print(body, 8))
            raise socket.timeout(e)

        status = self.status = resp.getcode()

        # Informational output
        if self.verbose or not self.quiet:
            log.info('Received ' + str(status))
        else:
            log.quiet('         ...Received ' + str(status))

        # Debug output
        log.debug('    Request: ' + method + ' ' + self.base_url + full_uri)
        if body:
            log.debug(pretty_print(body, 8))
        log.debug('    Response: ' + str(status))

        # Get the raw response
        self.data = resp.read()
        if self.data:
            try:
                # decode forces compatibility with python3 stings (can't be done on binary data)
                self.data = self.data.decode('utf-8')
            except:
                # Was not decoded... Don't try anything else (raw result is in data)
                pass
            else:
                # Was utf-8 decoded
                try:
                    # Try json parsing
                    self.data = pretty_print(json.loads(self.data), 8)
                except:
                    # Did not parse as json (result is plain text)
                    pass
                # Log the text data
                log.debug(self.data)

        if status == 422:
            try:
                json_resp = json.loads(self.data)
                if json_resp.get('errors'):
                    errors = []
                    for error in json_resp.get('errors'):
                        errors.append(error.get('text'))
                    raise SgaInstaller.ConfigError('  ' + '\n  '.join(errors))
                elif json_resp['message'].get('text'):
                    raise SgaInstaller.ConfigError('  ' + json_resp['message']['text'])
                else:
                    raise SgaInstaller.ResponseError(status)
            except SgaInstaller.ConfigError as e:
                raise
            except:
                raise SgaInstaller.ResponseError(status)
        if status < 200 or status >= 300:
            raise SgaInstaller.ResponseError(status)

        # Get the headers so we can use them in other methods
        self.headers = resp.headers

        return(self.data)

    def set_protocol_v1(self):
        '''Reconfigure headers for use with API v1'''
        self.base_uri = ''
        self.ctype = 'text/plain'


    def update_ip(self, ip):
        '''Reconfigure the IP target of API requests'''
        self.ip = ip
        if self.secure:
            self.upgrade_to_https()
        else:
            self.downgrade_to_http()


    def downgrade_to_http(self):
        '''Set the API request mode to HTTP (insecure)'''
        # Raise an error and exit if the no-insecure option is set
        if args.no_insecure:
            log.warn("Attempted to downgrade to insecure HTTP API communication.")
            raise DataInconsistencyError("Attempted to downgrade to HTTP communication with --no-insecure option set.")
        self.base_url = "http://{host}:{port}".format(host=self.ip, port=API_INSECURE_PORT)
        self.secure = False
        self.opener = urllib_request.build_opener(urllib_request.HTTPHandler())


    def upgrade_to_https(self):
        '''Set the API request mode to HTTPS'''
        self.base_url = "https://{host}:{port}".format(host=self.ip, port=API_SECURE_PORT)
        self.secure = True
        if _has_ssl_support:
            if sys.version_info < (2, 7, 9):
                # HTTPS requests from before 2.7.9 did not validate certificates and did not support SSL context
                self.opener = urllib_request.build_opener(urllib_request.HTTPSHandler())
            elif sys.version_info < (3, 0):
                # HTTPS SSL context was added in 2.7.9, so use if for all later 2.x versions
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                # Disable non-TLSv1.2/1.3 modes since the API never supported them.
                ctx.options &= ~ssl.OP_NO_SSLv2
                ctx.options &= ~ssl.OP_NO_SSLv3
                ctx.options &= ~ssl.OP_NO_TLSv1
                ctx.options &= ~ssl.OP_NO_TLSv1_1
                self.opener = urllib_request.build_opener(urllib_request.HTTPSHandler(context=ctx))
            elif sys.version_info < (3, 2):
                # Python 3.x before 3.2 did not support SSL context
                self.opener = urllib_request.build_opener(urllib_request.HTTPSHandler())
            else:
                # HTTPS SSL context and check_hostname are supported in 3.x starting at 3.2
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                # Disable non-TLSv1.2/1.3 modes since the API never supported them.
                ctx.options &= ~ssl.OP_NO_SSLv2
                ctx.options &= ~ssl.OP_NO_SSLv3
                ctx.options &= ~ssl.OP_NO_TLSv1
                ctx.options &= ~ssl.OP_NO_TLSv1_1
                self.opener = urllib_request.build_opener(urllib_request.HTTPSHandler(context=ctx, check_hostname=False))
        else:
            log.warn("API requests are configured for HTTPS, but SSL support is not present")
            self.opener = None


class Log:
    '''Logging to a file and the screen'''

    def __init__(self, logfile):
        '''Constructor for the Log class'''

        self.logfile = logfile

        if logfile:
            logging.basicConfig(level=logging.DEBUG, filename=logfile, filemode='a+',
                                format='%(asctime)-15s %(levelname)-8s %(message)s')

    def debug(self, msg, lf=True):
        '''Handle debug output'''
        if args.verbose:
            if lf:
                print(msg)
            else:
                sys.stdout.write(msg)
            sys.stdout.flush()  # For compatibility with python2 and 3
        if self.logfile:
            logging.debug(msg)

    def error(self, msg, lf=True):
        '''Handle error output'''
        if lf:
            sys.stderr.write(msg + '\n')
        else:
            sys.stderr.write(msg)
        sys.stderr.flush()  # For compatibility with python2 and 3
        if self.logfile:
            logging.error(msg)

    def info(self, msg, lf=True):
        '''Handle informational output'''
        if lf:
            print(msg)
        else:
            sys.stdout.write(msg)
        sys.stdout.flush()  # For compatibility with python2 and 3
        if self.logfile:
            logging.info(msg)

    def quiet(self, msg):
        '''Log only to the file'''
        if self.logfile:
            logging.info(msg)


    def exception(self, *args, **kwargs):
        '''Log an exception'''
        if self.logfile:
            logging.exception(*args, **kwargs)
        else:
            traceback.print_exc()


class ApplianceInstallationError(Exception):
    '''Raise a custom error when the appliance installation has failed.'''

    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class ApplianceNotReadyError(Exception):
    '''Raise a custom error when the appliance is not in "install" mode.'''

    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class ApplianceTimeoutError(Exception):
    '''Raise a custom error when waiting for the appliance times out.'''

    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class DataInconsistencyError(Exception):
    '''Raise a custom error when there is a data issue.'''

    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class DataInconsistencyWarning(Exception):
    '''Raise a custom warning when there is a data issue.'''

    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


def main():
    '''Main logic begins here.'''

    # Globals (so we don't have to pass these everywhere)
    global devices
    global log
    global sga
    global version

    devices = ['grid', 'admin', 'client']

    # Catch 22, we need a logfile in case parse fails
    # But we don't know what the logfile should be until we parse
    log = Log(None)

    parse_args()
    log = Log(args.logfile)

    # Create an appliance Installer object (for http calls)
    sga = SgaInstaller(args.sga_install_ip, args.verbose)

    # Get the version of the SGA API (pass major version supported by this script)
    version = get_version(2)

    # If version is 2.0 or newer, use v2
    if version >= (2, 0):
        main_v2()
    # Use v1
    else:
        main_v1()


def main_v2():

    # Globals (so we don't have to pass these everywhere)
    # Also, they are only updated when changes are expected
    global admin_connection
    global install_status
    global link_config
    global networks
    global system_config
    global system_info

    # Reboot the appliance
    if args.parser == 'reboot':
        sga.call('POST', '/reboot', {'swapActive': False})
        log.info('Reboot initiated... Please wait up to 5 minutes before reconnecting.')
        sys.exit(0)

    # Get system info as the first real API call after validating the version
    # Allow for a few retries in case the API is still in startup and not yet ready
    # to serve requests other than API versions.
    for retry_count in range(1,4):
        try:
            system_info = json.loads(sga.call('GET', '/system-info'))['data']
            break
        except SgaInstaller.ResponseError as e:
            # Catch and retry 503 ("The server is still initializing. Try again later.") errors
            if e.message == 503:
                # Limit this to 3 retries
                if retry_count < 3:
                    log.info("API reports service unavailable. Retrying.", lf=True)
                    sleep(args.poll_time)
                    continue
            # Anything other than 503 (and less than 3 retries) gets re-raised and should cause a failure
            raise

    # /admin-connection needed by configure_sga_v2 and show_config_v2
    admin_connection = json.loads(sga.call('GET', '/admin-connection'))['data']
    link_config = json.loads(sga.call('GET', '/link-config'))['data']
    networks = json.loads(sga.call('GET', '/networks'))['data']
    system_config = json.loads(sga.call('GET', '/system-config'))['data']

    # See if a prior attempt failed to install
    if system_info['installFailed']:
        # Query /install-status to get the errors
        install_status = json.loads(sga.call('GET', '/install-status'))['data']
            # This call does not return
        install_status_errors('/system-info API has "installFailed" flag')

    if args.parser == 'configure':
        if not system_info['installing']:
            configure_sga_v2()
        else:
            raise DataInconsistencyError('Installation is already in progress, configuration changes cannot be performed.\n' +
                                         '  Use "monitor" sub-command to monitor it.')

    # Show the configuration
    show_config_v2()

    if install_args.install:
        if system_info.get('maintenanceMode'):
            raise DataInconsistencyError(
                'This node is in maintenance mode. You cannot start an install.\n' +
                'Perform any required maintenance procedures, then reboot the node to resume normal operation.')
        if not system_info['installing']:
            log.info('Prepare for installation.')
            if system_info['needsAttention'] and not args.ignore_warnings:
                raise DataInconsistencyError(
                    'Installation cannot start. The appliance hardware needs attention.\n' +
                    '  Use SANtricity software to check and resolve the issue.\n' +
                    '  Use --ignore-warnings to override')
            if system_info.get('networkError'):
                raise DataInconsistencyError(
                    'Installation cannot start. The network IP configuration has errors.\n' +
                    'Correct the network settings before continuing.')
            if system_info.get('compatibilityError'):
                raise DataInconsistencyError(
                    'Installation cannot start. The appliance has configuration incompatibilities.\n' +
                    'Correct the configuration settings before continuing.')
            if admin_connection['connectionState'] != 'ready':
                wait_for_primary_admin_v2(install_args.timeout * 60)
                # Update system_info (now that we can connect to the PA)
                system_info = json.loads(sga.call('GET', '/system-info'))['data']
            for dev in devices:
                if networks['interfaces'].get(dev):
                    # Make sure we have DHCP address on all DHCP ports
                    wait_for_dhcp_v2(dev)

            # Not checking 'canInstall' - We do not have additional info as to why not
            # We just recently confirmed the admin-node was configured
            # If 'networkConfigured is true', start the install
            if system_info['networkConfigured']:
                # Start the install
                log.info('Start the installation.')
                # If this fails, an error will get raised
                install_status = json.loads(sga.call('POST', '/start-install'))['data']
                # sga.call('POST', '/start-install')
                # Get updated installing status
                system_info = json.loads(sga.call('GET', '/system-info'))['data']
                # If install does not start immediately, wait for poll time and check for install status.
                # This is a workaround for issue that causes install to not start immediately.
                if not system_info['installing']:
                    sleep(args.poll_time)
                    install_status = json.loads(sga.call('GET', '/install-status'))['data']
                    system_info = json.loads(sga.call('GET', '/system-info'))['data']
            else:
                raise DataInconsistencyError('Installation cannot start, the Grid Network has not been configured.\n' +
                                             '  Use "configure" sub-command to configure it.\n' +
                                             '  Possible options: --grid-cidr, --add-grid-route, --del-grid-route,' +
                                             '                    --grid-vlan-idm, --grid-bond-mode.')

        else:
            raise DataInconsistencyError('Installation is already in progress, installation cannot be started.\n' +
                                         '  Use "monitor" sub-command to monitor it.')

    elif not monitor_args.monitor:
        print_hashed(['If you are satisfied with this configuration,',
                      'execute the script with the "install" sub-command.'])
        sys.exit(0)

    if monitor_args.monitor:
        if system_info['installing']:
            # If we did not also install, the install_status needs initialization
            if not install_args.install:
                install_status = json.loads(sga.call('GET', '/install-status'))['data']
            monitor_install_v2()
        else:
            raise DataInconsistencyError('Cannot monitor installation as installation has not started.')


def main_v1():

    global devices

    # The devices list holds the bridges used in the order presented in the GUI
    devices = ['br1', 'br0']

    # Append br2 (Client Network) introduced in versions 1.5
    if version >= (1, 5):
        devices.append('br2')

    log.info('Checking installation status')
    networking = json.loads(sga.call('GET', '/networking'))

    # Get the install status
    install_status = networking['status']['install']['status']

    if args.parser == 'reboot':
        sga.call('POST', '/sys/soft_reboot')
        log.error('Reboot initiated... Please wait up to 5 minutes before reconnecting.')
        sys.exit(0)

    if install_status not in ['started', 'not started']:
        flat_status = flatten_status(json.loads(sga.call('GET', '/provisioning/json')))
        check_failed_items(flat_status)
        # If there were failed items, this line is not reached
        raise DataInconsistencyError('Appliance is in a "' + install_status + '" state, ' +
                                     'installation cannot be started.\n' +
                                     '  Address issues, then use the "reboot" sub-command to get out of this state.')

    if args.parser == 'configure':
        if install_status == 'not started':
            networking = configure_sga_v1(networking)
        else:
            raise DataInconsistencyError('Installation is already in progress, configuration changes cannot be performed.\n' +
                                         '  Use "monitor" sub-command to monitor it.')

    # Show the configuration
    show_config_v1()

    if install_args.install:
        if install_status == 'not started':
            wait_for_primary_admin_v1()

            # Start the install
            log.info('Start the installation.')
            sga.call('POST', '/provisioning/start')
            install_status = 'started'

        else:
            raise DataInconsistencyError('Installation is already in progress, installation cannot be started.\n' +
                                         '  Use "monitor" sub-command to monitor it.')

    elif not monitor_args.monitor:
        print_hashed(['If you are satisfied with this configuration,',
                      'execute the script with the "install" sub-command.'])
        sys.exit(0)

    if monitor_args.monitor:
        if install_status == 'started':
            monitor_install_v1()
        else:
            raise DataInconsistencyError('Cannot monitor installation as installation has not started.')

    sys.exit(0)


def signal_handler(signal, frame):
    ''''Trap Ctrl+C'''
    sys.exit(1)


if __name__ == '__main__':
    '''Call main() and trap the known errors.'''

    # Catch Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)

    try:
        main()
    except urllib_error.URLError as e:
        log.error('Error: Unable to communicate with the appliance.')
        log.error('  Received: ' + str(e))
        sys.exit(1)
    except SgaInstaller.ConfigError as e:
        log.error('Error: Received configuration error code from the appliance:\n' + str(e))
        sys.exit(1)
    except SgaInstaller.ResponseError as e:
        log.error('Error: Received unexpected return code from the appliance: ' + str(e))
        log.error('  ' + str(sga.data))
        sys.exit(1)
    except ApplianceInstallationError as e:
        log.error('Error: ' + str(e))
        sys.exit(2)
    except ApplianceNotReadyError as e:
        log.error('Error: ' + str(e))
        sys.exit(2)
    except ApplianceTimeoutError as e:
        log.error('Error: ' + str(e))
        sys.exit(3)
    except (DataInconsistencyError, AssertionError) as e:
        log.error('Error: ' + str(e))
        sys.exit(5)
    except DataInconsistencyWarning as e:
        log.error('Warning: ' + str(e))
        sys.exit(5)
