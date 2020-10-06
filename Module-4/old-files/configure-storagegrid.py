#!/usr/bin/python
#
# Copyright (c) 2016-2018 NetApp, Inc., All Rights Reserved
#
# Overview:
#   Script to configure StorageGRID after deployment of nodes.
#
#   Start with the sample configuration file and modify it for your deployment.
#
#   Exit status:
#   0 - Script executed successfully
#   1 - There were unknown results, review the output
#   2 - Primary Admin Node not in install mode or install cannot continue
#   3 - Primary Admin Node time-out (could not connect to the primary Admin Node)
#   4 - Grid Node time-out (all nodes did not register with the primary Admin Node)
#   5 - Inconsistent data, review the output
#
# NOTE:
#   This script has been verified with Pyton versions: 2.6.8, 2.7.6, 2.7.9 and 3.4.2
#

import argparse
import base64
import copy
import getpass
import json
import logging
import os
import pprint
import re
import ssl
import signal
import sys
from time import localtime, time, sleep, strftime
import traceback
import zipfile

if sys.version_info < (3, 0):
    import urllib2 as urllib_request
    import urllib2 as urllib_error
    import urllib2 as urllib_parse
    from httplib import BadStatusLine
else:
    import urllib.request as urllib_request
    import urllib.error as urllib_error
    import urllib.parse as urllib_parse
    from http.client import BadStatusLine
    basestring = str
    unicode = str


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

    # Use our parser with overloaded error method
    parser = ArgParser(description='Configure StorageGRID after deployment of nodes. ' +
                       'Modify sample configuration for your deployment.')
    # Required positional arguments
    parser.add_argument('config_file', help='JSON configuration file ' +
                        '(example available in "configure-storagegrid.sample.json")',
                        type=argparse.FileType('r'), default='-', metavar='CONFIG-FILE')

    # Optional arguments
    parser.add_argument('-a', '--admin-timeout',
                        help='Minutes to wait for the primary Admin Node (default 10).',
                        type=int, default=10, metavar='MINUTES')
    parser.add_argument('-c', '--skip-configure',
                        help='Skip configuration API calls.', action='store_true')
    parser.add_argument('-e', '--ignore-extra-nodes',
                        help='Ignore extra Grid Nodes registered with the primary Admin Node.',
                        action='store_true')
    parser.add_argument('--exit-early',
                        help='Monitor the release until the Primary Admin Node verifies all StorageGRID ' +
                        'nodes are in a healthy state and exit early. If this option is not supplied, the ' +
                        'script will monitor until the Primary Admin Node is 100 percent deployed.',
                        action='store_true')
    parser.add_argument('-i', '--start-install',
                        help='Installation is not performed unless this option is specified.', action='store_true')
    parser.add_argument('-j', '--join-install',
                        help='Monitor the installation of a StorageGRID installation ' +
                        'where the installation is already in progress.',
                        action='store_true')
    parser.add_argument('-l', '--license-file',
                        help='Provide the StorageGRID license from a file (ignores the license entry in the config_file).',
                        metavar='LICENSE-FILE')
    parser.add_argument('--logfile',
                        help='Log file for verbose logging (--verbose not required)',
                        metavar='LOGFILE')
    parser.add_argument('--monitor-delta',
                        help='Summarized monitoring information; an alternative to the tabular output.',
                        action='store_true')
    parser.add_argument('-n', '--reset-node-configuration',
                        help='Revert all grid nodes to pending and remove previous configuration ' +
                        'before applying the new grid node configuration.', action='store_true')
    parser.add_argument('-p', '--passwords',
                        help='Prompt for the passwords and ignore the entries in the config file.',
                        action='store_true', default=None)
    parser.add_argument('--poll-time', help='Seconds to sleep during polling intervals (default 10).',
                        type=int, default=10, metavar='SECONDS')
    parser.add_argument('-r', '--recovery-package-path',
                        help='Provide the directory to save the "recovery package" into (directory must exist). ' +
                        'If not specified, the present working directory is used.',
                        default='.', metavar='DIRECTORY')
    parser.add_argument('-s', '--site-delete',
                        help='Delete all existing sites.', action='store_true')
    parser.add_argument('-t', '--timeout',
                        help='Minutes to wait for Grid Nodes to register with the primary Admin Node(default 10).',
                        type=int, default=10, metavar='MINUTES')
    parser.add_argument('-v', '--verbose',
                        help='Verbose output (shows API calls in <STDOUT>).', action='store_true')

    args = parser.parse_args()

    if args.start_install and args.join_install:
        raise DataInconsistencyError('Cannot specify both --start-install and --join-install.\n' +
                                     '  Specify --help for detailed usage.')

    # Check that we can write to the directory where we'll save the "recovery package"
    if not os.access(args.recovery_package_path, os.W_OK):
        raise DataInconsistencyError('Could not write to directory "' + args.recovery_package_path + '".\n'
                                     '  Use --recovery-package-path to specify a writable directory.')

    if not args.start_install and not args.join_install and args.monitor_delta:
            raise DataInconsistencyError('Option --monitor-delta requires --start-install or --join-install.\n'
                                         '  Specify --help for detailed usage.')

    if not args.start_install and not args.join_install and args.exit_early:
            raise DataInconsistencyError('Option --exit-early requires --start-install or --join-install.\n'
                                         '  Specify --help for detailed usage.')


def update_license(license_file, config):
    '''Open the license file, base64 encode it then update config'''

    try:
        json_lic = open(license_file).read()
    except IOError as e:
        raise DataInconsistencyError(e)

    # encode/decode force python3 compatibility
    b64_lic = base64.b64encode(json_lic.encode('utf-8'))
    config['grid-details']['license'] = b64_lic.decode('utf-8')

    return(config)


def prompt_for_password(display_name):
    '''Prompt for a single password and return it'''

    while True:
        password = getpass.getpass('Enter ' + display_name + ': ')
        password2 = getpass.getpass('Enter ' + display_name + ' again: ')
        if password != password2:
            print('Passwords did not match.\n')
            print('Try again.')
        else:
            break

    return(password)


def update_passwords(config):
    '''Prompt for all passwords then update config'''

    config['passwords']['management'] = prompt_for_password(
        'grid management root user password')
    config['passwords']['provision'] = prompt_for_password(
        'provisioning passphrase')

    return(config)


def wait_for_primary_admin():
    '''Perform GET "start" API call to check communication with the primary Admin Node.'''

    waiting = True
    gmi_api.quiet = True
    # Get the epoch time, add the timeout
    epoch_timeout = time() + args.admin_timeout * 60
    log.info('Connecting to https://' + gmi_api.address + ' ("primary-admin-api-address" from ' +
             args.config_file.name + ')')
    while waiting:
        try:
            # Perform a GET on "start"... Retrieves status of the install
            status = json.loads(gmi_api.call('GET', 'start'))
        except urllib_error.URLError as e:
            log.info('Waiting for primary Admin Node: ' + gmi_api.address + ' (cannot connect)')
            if time() >= epoch_timeout:
                raise AdminTimeoutError('Timed out waiting for primary Admin Node.')
            sleep(args.poll_time)
        except GmiApi.ResponseError as e:
            # A 503 can occur if Apache is up but Ruby is not yet listening (keep waiting)
            if e.status == 503:
                log.info('Waiting for primary Admin Node: ' + gmi_api.address + ' (received 503)')
                if time() >= epoch_timeout:
                    raise AdminTimeoutError('Timed out waiting for primary Admin Node.')
                sleep(args.poll_time)
            elif e.status == 405:
                raise AdminNotReadyError('Primary Admin Node is not in install mode.')
            else:
                raise GmiApi.ResponseError(e)
        else:
            log.info('Connection verified (received ' + str(gmi_api.status) + ')')
            waiting = False
    gmi_api.quiet = False

    return(status)


def reset_all_nodes():
    '''Perform GET "nodes" API call then reset the accepted nodes.'''

    # Perform a GET on "nodes"... Retrieves array of nodes having registered with the primary Admin Node
    nodes = json.loads(gmi_api.call('GET', 'nodes'))
    for node in nodes['data']:
        # Reset the association of the previously configured nodes
        if node['configured']:
            gmi_api.call('POST', 'nodes/' + node['id'] + '/reset')


def delete_all_sites():
    '''Perform GET "sites" API call then "DELETE" them.'''

    # Perform a GET on "sites"... Retrieves array of previously created sites
    sites = json.loads(gmi_api.call('GET', 'sites'))
    for site in sites['data']:
        # Delete the association of the previously configured nodes
        gmi_api.call('DELETE', 'sites/' + site['id'])


def create_sites(config_sites):
    '''Get the list of sites...
    Create only the new ones listed in the config-file.
    Return a data structure of all sites.'''

    # Perform a GET on "sites"... Retrieves array of existing sites
    sites = json.loads(gmi_api.call('GET', 'sites'))

    data = {}
    for site in sites['data']:
        # Populate some hashes to use in next block
        data[site['name']] = {'id': site['id']}

    # Iterate through the sites we want to create
    for new_site in config_sites:
        if new_site['name'] in data.keys():
            log.info('Site name "' + new_site['name'] + '" Already exists... Not creating.')
        else:
            try:
                site = json.loads(gmi_api.call('POST', 'sites', new_site))['data']
                data[site['name']] = {'id': site['id']}
            # Bug 0029539 - A low-level retry may have succeeded
            except GmiApi.ResponseError as e:
                # Store the original gmi_api.data (the call below will overwrite it)
                found_site = False
                try:
                    # Check the return code for a match
                    if e.status == 422:
                        # 422 implies a validation error with the data
                        # See if one of the "faile" API calls created the site
                        sites = json.loads(gmi_api.call('GET', 'sites'))['data']
                        for site in sites:
                            if new_site['name'] == site['name']:
                                # Eureka!!!
                                found_site = True
                                data[site['name']] = {'id': site['id']}
                                break
                except:
                    # Something went wrong, raise the original error
                    raise GmiApi.ResponseError(e)

                if not found_site:
                    # Nothing went wrong, but site not found, raise the original error
                    raise GmiApi.ResponseError(e)
    return(data)


def update_nodes(config_nodes, site_data):
    '''Get the list of nodes...
    Accept and configure the ones listed in the config-file.
    Raise if an unexpected node registers.'''

    node_status = {}
    all_nodes_registered = False
    # Get the epoch time, add the node-timeout
    epoch_timeout = time() + args.timeout * 60
    while not all_nodes_registered:
        # Perform a GET on "nodes"... Retrieves array of nodes having registered with the primary Admin Node
        nodes = json.loads(gmi_api.call('GET', 'nodes'))

        # Iterate through the nodes we expect to update (from config_file)
        for addr, node_config in config_nodes.items():
            # See if this node is in the list of registered nodes
            node_data = get_node_data(addr, node_config, nodes['data'])
            if node_data:
                # See if this node needs updating in this iteration
                if node_status.get(addr) != 'updated':
                    # Mark as updated
                    node_status[addr] = 'updated'
                    # Get the node's id (used in the api URL)
                    node_id = node_data['id']

                    try:
                        # Update the node's site (look up id in site_data)
                        node_data['site'] = site_data[node_config['siteName']]['id']
                    except KeyError as e:
                        raise DataInconsistencyError('Could not find site: ' + str(e))

                    # Structure update (update or add elements from node['nodeData'] - no deletes)
                    structure_update(node_config['nodeData'], node_data)

                    # Update the node
                    gmi_api.call('PUT', 'nodes/' + node_id, node_data)
            else:
                node_status[addr] = 'unregistered'
                log.info('Waiting for "' + addr + '" to register.')

        # Check node_status if any are tagged 'unregistered' Then we're still waiting
        if 'unregistered' in node_status.values():
            if time() >= epoch_timeout:
                raise NodeTimeoutError('Timed out waiting for nodes to register.')
            sleep(args.poll_time)
        else:
            # All expected nodes registered... Flag for exit of loop
            all_nodes_registered = True

    # All nodes registered...
    # Check for unexpected nodes (unless --ignore-extra-nodes was specified)
    if not args.ignore_extra_nodes:
        extra_nodes = []
        for node in nodes['data']:
            found_addr_in_node = False
            for addr, node_config in config_nodes.items():
                if node == get_node_data(addr, node_config, nodes['data']):
                    found_addr_in_node = True
                    break
            if not found_addr_in_node:
                extra_nodes.append(node)

        if extra_nodes:
            log.info('Warning: There were unexpected nodes registered with the primary Admin Node:')
            for node in extra_nodes:
                ip = node['networks']['grid']['ip'].split('/')[0]
                print_hashed(['An unexpected node has registered with the primary Admin Node.',
                              'Node IP: {} Name: {} Type: {} Either add it to the configuration ({}),'.
                              format(ip, str(node['name']), str(node['type']), args.config_file.name),
                              'or execute this script with --ignore-extra-nodes.'])
            raise DataInconsistencyError()


def get_node_data(addr, node_config, nodes_data):
    '''Search for the address as in IP or as the node-name'''
    for node in nodes_data:
        # Grab the IP of this particular node
        ip = node['networks']['grid']['ip'].split('/')[0]
        if addr == ip:
            # Found by IP
            return(node)
        if addr == node['name']:
            # If we're matching the name assure we're not renaming the node
            config_name = node_config['nodeData'].get('name')
            if config_name:
                if node['name'] != config_name:
                    raise DataInconsistencyError(str('Validation failed in "{0}".\n    ' +
                                                     'The JSON object ("nodes": {{"{1}": {{"nodeData": ' +
                                                     '{{"name": "{2}"}}}}}}) does not match "{1}".').
                                                 format(args.config_file.name, addr, config_name))
            # Found by name
            return(node)
    return False


def start_and_monitor_install(start=True, status=None):
    '''Start and monitor the progress of the installation'''

    if start:
        # Perform a POST on "start"... Kick off the install
        gmi_api.call('POST', 'start')

        # The "POST" which starts the install returns a "202" (accepted)
        # It takes just a moment to start
        # This sleep is enough to avoid a race condition with the "GET" (just below).
        sleep(args.poll_time)

    # Check result of status API call... See if we're provisioning
    while not status or status['data']['inProgress']:
        log.info('StorageGRID provisioning is in progress.')
        sleep(args.poll_time)
        # Make sure install is in progress
        try:
            # Perform a GET on "start"... Retrieves status of the install
            status = json.loads(gmi_api.call('GET', 'start'))
        except GmiApi.ResponseError as e:
            # A 405 is received when a stable system is no longer installing
            if e.status == 405:
                print_hashed(['StorageGRID has been configured and installed.'])
                sys.exit(0)
            else:
                # There are other error codes right after provisioning
                # We won't get those unless we were joining a deployment in progress
                # Just error out and let the user tyr again
                raise GmiApi.ResponseError(e)

    # See if provisioning had a problem
    if status['data']['error']:
        raise AdminNotReadyError('Provisioning error: ' + status['data']['error'])

    # Try to download and verify the recovery-package
    recovery_package_verify()

    # If we're joining the install, the nodes variable will be undefined
    try:
        nodes
    except UnboundLocalError:
        nodes = []

    nodes_delta = []
    while True:
        gmi_api.quiet = True
        try:
            time_string = strftime('%Y/%m/%d %H:%M:%S: ', localtime())
            log.info(time_string + 'Retrieving node information')
            nodes = json.loads(gmi_api.call('GET', 'nodes'))
        except GmiApi.ResponseError as e:
            if e.status == 405:
                try:
                    nodes['data']
                except:
                    pass
                else:
                    print_nodes_table(nodes['data'])
                    unconfigured_nodes(nodes['data'])
                print_hashed(['StorageGRID has been configured and installed.'])
                sys.exit(0)
            elif e.status >= 500:
                log.info('The StorageGRID install API is restarting or not responding.')
                if not nodes:  # We need to try again if nodes was empty
                    continue
            else:
                raise GmiApi.ResponseError(e)
        else:
            if args.monitor_delta:
                if len(nodes_delta) == 0:
                    print_nodes_table(nodes['data'])
                    nodes_delta = nodes
                else:
                    print_nodes_delta(nodes['data'], nodes_delta['data'])
                    nodes_delta = nodes
            else:
                print_nodes_table(nodes['data'])
        gmi_api.quiet = False

        # If exiting early, confirm download of the recovery package ASAP
        # If not, wait until the Primary Admin Node is waiting for the download
        # Only "confirm" if the package has been validated and has not been confirmed
        if (args.exit_early or primary_admin_waiting_for_confirmation(nodes['data'])) and \
                recovery_package_verify.status and not recovery_package_confirm.status:
            # This call confirms to the system the "recovery package" was downloaded
            recovery_package_confirm()

            # Check if we're here because the Primary Admin Node was waiting for confirmation,
            if primary_admin_waiting_for_confirmation(nodes['data']):

                print_nodes_table(nodes['data'])

                # do not exit this block until the Primary Admin Node is available
                while True:
                    gmi_api.quiet = True
                    try:
                        time_string = strftime('%Y/%m/%d %H:%M:%S: ', localtime())
                        log.info(time_string + 'Retrieving node information')
                        json.loads(gmi_api.call('GET', 'nodes'))
                    except GmiApi.ResponseError as e:
                        if e.status == 405:
                            unconfigured_nodes(nodes['data'])
                            print_hashed(['StorageGRID has been configured and installed.'])
                            sys.exit(0)
                        elif e.status >= 500:
                            log.info('The StorageGRID install API is restarting or not responding.')
                        else:
                            raise GmiApi.ResponseError(e)
                    except urllib_error.URLError as e:
                        # Apache is stopped while mgmt-api restarts into post-install mode.
                        # Keep looping even if we get a URL connection error.
                        log.info('The StorageGRID install web server is restarting or not responding.')

                    sleep(args.poll_time)
                    gmi_api.quiet = False

        # Check if any nodes have an error condition
        for node in nodes['data']:
            if node['progress']['error'] and node['progress']['error'] != '':
                raise AdminNotReadyError('Provisioning error: ' + node['name'] + ' Error: ' + node['progress']['error'])

        sleep(args.poll_time)


def recovery_package_verify():
    try:
        # Call the recovery-package API; downloads a zip file
        gmi_api.call('GET', 'recovery-package')
        # Save the zip file
        saved_file = gmi_api.save_file(args.recovery_package_path)
        recovery_package_verify.saved_file = saved_file

        # Verify the "recovery package" can be unzipped
        f = zipfile.ZipFile(saved_file, 'r')
        # Checking for this directory in the archive verifies it
        f.getinfo('gpt-backup/')
        f.close()
        # Will not reach this line unless the recovery package was verified
        log.info("Downloaded recovery package {}".format(recovery_package_verify.saved_file))
        recovery_package_verify.status = True
    except:
        print_hashed(['There was an error retrieving the "recovery package" zip file.',
                      'Direct your browser to: https://' + gmi_api.address +
                      '/install/#/install/status',
                      'and follow the instructions.'])


def recovery_package_confirm():
    # This call confirms to the system the "recovery package" was downloaded
    # The call is required in order for installation to finish
    gmi_api.call('POST', 'recovery-package-confirm')
    print_hashed(['The StorageGRID "recovery package" has been downloaded as:',
                 recovery_package_verify.saved_file, 'Safeguard this file as it will be needed in case of a',
                 'StorageGRID node recovery.'])
    recovery_package_confirm.status = True


# Instance variables to control flow in above functions
recovery_package_verify.status = False
recovery_package_confirm.status = False


def primary_admin_waiting_for_confirmation(nodes_data):
    ''' Find the Primary Admin Node in the nodes_data and see if it is waiting for "confirmation" '''
    waiting_for_confirmation = False
    for node in nodes_data:
        if node['isPrimaryAdmin']:
            if node['progress']['stage'] and \
                    node['progress']['stage']['key'] == 'maintenance.install.steps.waitForDownload.name':
                # The Primary Admin Node will not reach 100% complete, so fake it
                node['progress']['percentage'] = 100
                node['progress']['stage']['text'] = 'Complete'

                waiting_for_confirmation = True
            break

    return(waiting_for_confirmation)


def structure_update(source, target):
    '''Update (add or update) structures from source onto target.'''

    if isinstance(source, dict) and isinstance(target, dict):
        for key, value in source.items():
            if isinstance(value, list):
                # Currently, no list structures exist in the target, so just disallow them
                raise DataInconsistencyError('Invalid source structure ("list" not allowed): "' + str(key) + '".')
            elif isinstance(value, dict):
                try:
                    # Get the boolean
                    target_key_dict = isinstance(target[key], dict)
                except KeyError:
                    # This whole structure did not exist, set from source
                    target[key] = value
                else:
                    if target_key_dict:
                        # Recursive call to update this dict
                        structure_update(value, target[key])
                    else:
                        raise DataInconsistencyError('Invalid structure update in target (needs to be "dict" or non-existent): "' +
                                                     str(key) + '".')
            else:
                # Update the individual item
                target[key] = value
    else:
        raise DataInconsistencyError('Invalid structure: source and target must be "dict".')


def pretty_print(s, num_spaces):
    '''Pretty print a JSON string'''
    s = json.dumps(s, indent=4)
    s = s.split('\n')
    s = [(num_spaces * ' ') + line for line in s]
    s = '\n'.join(s)
    return(s)


def print_nodes_delta(nodes_data, last_nodes_data):
    '''Only print the nodes which changed between nodes_data and last_nodes_data'''

    # Structure sizes need to be the same (otherwise something will break)
    if len(nodes_data) >= len(last_nodes_data):
        delta_nodes = []
        i = 0
        for node in nodes_data:
            try:
                # Structures are in the same order
                # If the name is not the same assume there's an additional node
                if str(node['name']) != str(last_nodes_data[i]['name']):
                    delta_nodes.append(node)
                    continue
                if str(node['progress']['percentage']) != str(last_nodes_data[i]['progress']['percentage']):
                    delta_nodes.append(node)
            except (KeyError, IndexError) as e:
                # If the structure was not healthy, quietly log and skip it
                log.quiet_exception(e)
            i += 1

        print_nodes_table(delta_nodes, False)

    else:
        log.debug("Error: Structures are different sizes\n" +
                  "Struct1: " + pprint.pformat(nodes_data, depth=2) + "\n" +
                  "Struct2: " + pprint.pformat(last_nodes_data, depth=2))


def print_nodes_table(nodes_data, full_output=True):
    '''Print a table from the nodes_data; one line per node
    full_output=True prints borders
    full_output=False prints without borders'''

    table = []
    if full_output:
        table.append(['Name', 'IP', 'Progress', 'Stage'])

    for node in nodes_data:
        if not node['progress']['stage']:
            if node['configured'] is False:
                stage = 'Unconfigured'
            else:
                stage = ''
        else:
            stage = node['progress']['stage']['text']
        table.append([str(node['name']), node['networks']['grid']['ip'],
                     '  %3d%%' % (node['progress']['percentage']), stage])
        if node['progress']['error'] and node['progress']['error'] != '':
            table.append(['', '', '  ', node['progress']['error']])

    # Get the column with and create a list
    col_width = [max(len(x) for x in col) for col in zip(*table)]

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


def unconfigured_nodes(nodes_data):
    '''Search for unconfigured nodes, print hashed output for each node'''

    for node in nodes_data:
        if node['configured'] is False:
            print_hashed(['Node ' + node['name'] + ' was registered with the',
                          'primary Admin Node after provisioning was complete.',
                          'To add this node to the grid, you must',
                          'perform an expansion procedure.'])


def print_hashed(msgs):
    '''Print a formatted column surrounded hashes'''

    # Get the column with and create a list
    width = max(len(x) for x in msgs) + 2

    msgs.insert(0, '#' * width)
    msgs.append('#' * width)

    # Iterate over the msgs
    for text in msgs:
        log.info('#####' + text.center(width) + '#####')


class GmiApi:
    '''GMI API class definition.'''

    class ResponseError(Exception):
        '''Raise a custom response error for non 200-299 results.'''

        def __init__(self, *args, **kwargs):
            if len(args) == 1 and isinstance(args[0], GmiApi.ResponseError):
                self.status = args[0].status
                self.data = args[0].data
            else:
                if len(args) > 0 and isinstance(args[0], int):
                    self.status = args[0]
                else:
                    self.status = None
                if len(args) > 1 and isinstance(args[1], basestring):
                    self.data = args[1]
                else:
                    self.data = None

            Exception.__init__(self, *args, **kwargs)

    quiet = False

    def __init__(self, address, verbose=False, https_verify=False):
        '''Initialize https configuration.'''

        self.address = address
        self.verbose = verbose
        self.base_url = None
        self.api_version = None

        try:
            # This block is compatible with python >= 2.7.9 (tested through 3.4)
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            if https_verify:
                context.verify_mode = ssl.CERT_REQUIRED
            else:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            self.opener = urllib_request.build_opener(urllib_request.HTTPSHandler(context=context))
        except AttributeError as e:
            # This string is detected in python 2.7.6 (during an exception)
            if "'module' object has no attribute 'SSLContext'" in str(e):
                # This opener is compatible with python 2.7.6
                self.opener = urllib_request.build_opener(urllib_request.HTTPSHandler())

    def call(self, method, api, body=None):
        '''Call the GMI API.
        Returns the response body.'''

        if self.api_version is None and api != 'versions':
            self.negotiate_api_version()

        # Encoding with utf-8 makes this compatible with python 3
        request = urllib_request.Request(self.base_url + api)
        if isinstance(body, str):
            request.data = body.encode('utf-8')
        elif body:
            request.data = json.dumps(body).encode('utf-8')
        elif method == 'POST':
            # There is no content for this POST
            # An empty string will force "Content-Length: 0"
            request.data = ''.encode('utf-8')

        request.get_method = lambda: method
        request.add_header('Accept', 'application/json, application/xml, text/*')
        request.add_header('Content-Type', 'application/json')

        retries = 5
        resp = None
        while retries:
            time_string = strftime('%Y/%m/%d %H:%M:%S: ', localtime())
            if self.verbose or not self.quiet:
                # Informational output
                sys.stdout.write(time_string + 'Performing ' + method + ' on ' + api + '... ')
                sys.stdout.flush()  # For compatibility with python2 and 3
            log.quiet(time_string + 'Performing ' + method + ' on ' + api + '... ')

            try:
                resp = self.opener.open(request)
            except urllib_error.HTTPError as e:
                resp = e
                # retry 5XX errors
                if resp.getcode() >= 500 and resp.getcode() < 600:
                    retries = retries - 1
                    if retries:
                        if self.verbose or not self.quiet:
                            # Informational output
                            sys.stdout.write('    Retrying on status ' + str(resp.getcode()) + '\n')
                            sys.stdout.flush()  # For compatibility with python2 and 3
                        log.quiet('    Retrying on status ' + str(resp.getcode()))
                        sleep(5)
                else:
                    retries = 0
            except urllib_error.URLError as e:
                retries = retries - 1
                if retries:
                    if self.verbose or not self.quiet:
                        # Informational output
                        sys.stdout.write('    Retrying on URLError (' + str(e) + ')\n')
                        sys.stdout.flush()  # For compatibility with python2 and 3
                    log.quiet('    Retrying on URLError (' + str(e) + ')')
                    sleep(5)
                else:
                    raise
            except BadStatusLine as e:
                retries = retries - 1
                if retries:
                    log.debug('    Retrying on BadStatusLine (' + str(e) + ')')
                    sleep(5)
                else:
                    raise
            else:
                retries = 0

        status = self.status = resp.getcode()

        # Informational output
        if self.verbose or not self.quiet:
            sys.stdout.write('Received ' + str(status) + '\n')
            sys.stdout.flush()  # For compatibility with python2 and 3
        log.quiet('         ...Received ' + str(status))

        # Debug output
        log.debug('    Request: ' + method + ' ' + self.base_url + api)
        if body:
            log.debug(pretty_print(body, 8))
        log.debug('    Response: ' + str(status))

        # Get the raw response
        self.data = resp.read()

        # Get the headers so we can use them in other methods
        self.headers = resp.headers

        if self.data:
            # See if we have JSON
            if self.headers['Content-Type'] == 'application/json':
                try:
                    # decode forces compatibility with python3 stings (can't be done on binary data)
                    self.data = self.data.decode('utf-8')
                except UnicodeError:
                    # Was not decoded... Don't try anything else (raw result is in data)
                    pass
                try:
                    # Try JSON parsing
                    self.data = pretty_print(json.loads(self.data), 8)
                except ValueError as e:
                    log.info("Failed to decode response data: " + str(e))
                # Log the data
                log.debug(str(self.data))
            else:
                # Not JSON, log the headers and length of the body
                for header, value in self.headers.items():
                    log.debug("Response Header: " + header + ': ' + value)
                log.debug("Data length: " + str(len(self.data)) + " bytes")

        if status < 200 or status >= 300:
            if self.data and self.headers['Content-Type'] == 'application/json':
                raise GmiApi.ResponseError(status, self.data)
            else:
                raise GmiApi.ResponseError(status)

        return(self.data)

    def negotiate_api_version(self):
        '''Calls the versions endpoint and selects the highest supported version.'''
        # This uses the handling logic in call, but that requires setting an
        # initial base_url value.
        self.base_url = 'https://' + self.address + '/api/'
        supported_versions = json.loads(gmi_api.call('GET', 'versions'))
        max_version = max(supported_versions['data'])
        # This version of the script supports up to API v3.
        if max_version > 3:
            max_version = 3
        # self.api_version must be populated after self.base_url is correct to
        # ensure that any failures still result in a consistent internal state.
        self.base_url = 'https://' + self.address + '/api/v' + str(max_version) + '/install/'
        self.api_version = max_version

    def save_file(self, path):
        '''Save a file from a previous call which retieved a file'''

        # Get the filename from the Content-Disposition header
        file = path.rstrip('/') + '/' + re.sub('^.*filename=', '',
                                               self.headers['Content-Disposition'])

        try:
            f = open(file, 'wb')
            f.write(self.data)
            f.close()
        except:
            raise Exception('File not saved')

        return(file)


class Log:
    '''Logging to a file and the screen'''

    def __init__(self, logfile):
        '''Constructor for the Log class'''

        self.logfile = logfile

        if logfile:
            logging.basicConfig(level=logging.DEBUG, filename=logfile, filemode='a+',
                                format='%(asctime)-15s %(levelname)-8s %(message)s')

    def debug(self, msg):
        '''Handle debug output'''
        if args.verbose:
            print(msg)
            sys.stdout.flush()  # For compatibility with python2 and 3

        if self.logfile:
            logging.debug(msg)

    def info(self, msg):
        '''Handle informational output'''
        print(msg)
        sys.stdout.flush()  # For compatibility with python2 and 3
        if self.logfile:
            logging.info(msg)

    def quiet(self, msg):
        '''Log only to the file'''
        if self.logfile:
            logging.info(msg)

    def quiet_exception(self, exc):
        '''Log exception only if verbose or if there's a logfile'''
        if args.verbose:
            traceback.print_exc()  # We don't specify the exc but traceback figures it out
            sys.stdout.flush()  # For compatibility with python2 and 3

        if self.logfile:
            logging.exception(exc)


class AdminNotReadyError(Exception):
    '''Raise a custom error when the primary Admin Node is not in "install" mode.'''

    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class AdminTimeoutError(Exception):
    '''Raise a custom error when waiting for the primary Admin Node timeout.'''

    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class NodeTimeoutError(Exception):
    '''Raise a custom error when waiting for all nodes to register with the primary Admin Node.'''

    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class DataInconsistencyError(Exception):
    '''Raise a custom error when there is a data issue.'''

    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


def main():
    '''Main logic begins here.'''

    # Globals (so we don't have to pass these everywhere)
    global gmi_api
    global log

    parse_args()
    log = Log(args.logfile)

    try:
        # Read the JSON config_file
        config = json.load(args.config_file)
        # Make a copy for validation purposes
        config_validate = copy.deepcopy(config)
    except (IOError, ValueError) as e:
        raise DataInconsistencyError('Could not parse "' + args.config_file.name + '".\n  ' + str(e))

    try:
        # All these keys should be found in the config_file
        assert type(config['primary-admin-api-address']) == unicode, \
            'Expecting "primary-admin-api-address" to be a string.'
        config_validate.pop('primary-admin-api-address')
        assert type(config['grid-details']) == dict, \
            'Expecting "grid-details" to be a JSON object.'
        assert type(config['grid-details']['name']) == unicode, \
            'Expecting "grid-details": {"name": } to be a string.'
        config_validate['grid-details'].pop('name')
        assert type(config['grid-details']['license']) == unicode, \
            'Expecting "grid-details": {"license": } to be a string.'
        config_validate['grid-details'].pop('license')
        if len(config_validate['grid-details'].keys()) > 0:
            extra_keys = ', '.join(config_validate['grid-details'].keys())
            raise DataInconsistencyError('Validation failed in "' + args.config_file.name + '".\n  ' +
                                         '  Found extra JSON object key(s) ("grid-details": {' + extra_keys + '}).')
        config_validate.pop('grid-details')
        assert type(config['passwords']) == dict, \
            'Expecting "passwords" to be a JSON object.'
        assert type(config['passwords']['management']) == unicode, \
            'Expecting "passwords": {"management": } to be a string.'
        config_validate['passwords'].pop('management')
        assert type(config['passwords']['provision']) == unicode, \
            'Expecting "passwords": {"provision": } to be a string.'
        config_validate['passwords'].pop('provision')
        if 'useRandom' in config['passwords']:
            assert type(config['passwords']['useRandom']) == bool, \
                'Expecting "passwords": {"useRandom": } to be boolean.'
            config_validate['passwords'].pop('useRandom')
        if len(config_validate['passwords'].keys()) > 0:
            extra_keys = ', '.join(config_validate['passwords'].keys())
            raise DataInconsistencyError('Validation failed in "' + args.config_file.name + '".\n  ' +
                                         '  Found extra JSON object key(s) ("passwords": {' + extra_keys + '}).')
        config_validate.pop('passwords')
        assert type(config['ntp-servers']) == list, \
            'Expecting "ntp-servers" to be an array.'
        config_validate.pop('ntp-servers')
        assert type(config['dns-servers']) == list, \
            'Expecting "dns-servers" to be an array.'
        config_validate.pop('dns-servers')
        assert type(config['grid-networks']) == list, \
            'Expecting "grid-networks" to be an array.'
        config_validate.pop('grid-networks')
        assert type(config['sites']) == list, \
            'Expecting "sites" to be an array.'
        config_validate.pop('sites')
        assert type(config['nodes']) == dict, \
            'Expecting "nodes" to be a JSON object.'
        for node in config['nodes']:
            assert type(config['nodes'][node]) == dict, \
                'Expecting "nodes": {"' + node + '": } to be a JSON object.'
            assert type(config['nodes'][node]['siteName']) == unicode, \
                'Expecting "nodes": {"' + node + '": {"siteName": }} to be a string.'
            config_validate['nodes'][node].pop('siteName')
            assert type(config['nodes'][node]['nodeData']) == dict, \
                'Expecting "nodes": {"' + node + '": {"nodeData": }} to be a JSON object.'
            config_validate['nodes'][node].pop('nodeData')
            if len(config_validate['nodes'][node].keys()) > 0:
                extra_keys = ', '.join(config_validate['nodes'][node].keys())
                raise DataInconsistencyError('Validation failed in "' + args.config_file.name + '".\n  ' +
                                             '  Found extra JSON object key(s) ("nodes": {"' + node + '": {' + extra_keys + ': }}.')

            config_validate['nodes'].pop(node)
        config_validate.pop('nodes')
        if len(config_validate.keys()) > 0:
            extra_keys = ', '.join(config_validate.keys())
            raise DataInconsistencyError('Validation failed in "' + args.config_file.name + '".\n  ' +
                                         '  Found extra JSON object key(s) (' + extra_keys + ').')
    except KeyError as e:
        key_name = re.sub("'", '"', str(e))
        if str(e) in ["'management'", "'provision'", "'useRandom'", "'name'", "'license'", "'siteName'", "'nodeData'"]:
            if str(e) in ["'management'", "'provision'", "'useRandom'"]:
                object_name = '"passwords": {' + key_name + ': }'
            elif str(e) in ["'name'", "'license'"]:
                object_name = '"grid-details": {' + key_name + ': }'
            else:
                object_name = '"nodes": {"' + node + '": {' + key_name + ': }}'
            raise DataInconsistencyError('Validation failed in "' + args.config_file.name + '".\n  ' +
                                         '  The JSON object key (' + object_name + ') does not exist.')
        else:
            raise DataInconsistencyError('Validation failed in "' + args.config_file.name + '".\n  ' +
                                         '  The JSON object key (' + key_name + ') does not exist.')
    except AssertionError as e:
        raise DataInconsistencyError('Validation failed in "' + args.config_file.name + '".\n  ' + str(e))

    if args.license_file:
        config = update_license(args.license_file, config)

    if args.passwords:
        config = update_passwords(config)
    elif (config['passwords']['management'] == '<Update with valid password>' or
            config['passwords']['provision'] == '<Update with valid password>'):
        raise DataInconsistencyError('Error: Default password is in the config_file.\n' +
                                     'Please change it.')

    # Grab the primary-admin-api-address from the config-file then create the GMI API object
    gmi_api = GmiApi(config['primary-admin-api-address'], args.verbose)

    status = wait_for_primary_admin()

    # Check if provisioning was started in some other session
    if status['data']['inProgress'] or status['data']['complete']:
        if args.join_install:
            print_hashed(['Deployment is already in progress.',
                          'Ignoring additional configuration parameters.',
                          'Monitoring deployment in progress.'])
            start_and_monitor_install(False, status)
            sys.exit(0)
        # If we're not joining an installation, we shouldn't have been here
        raise AdminNotReadyError('Primary Admin Node is not in install mode.\n' +
                                 '  Use --join-install to monitor a deployment already in progress.')

    # The only way to "join" is in the block above so error out
    if args.join_install:
        raise AdminNotReadyError('Installation is not in progress, cannot join.')

    if args.reset_node_configuration:
        reset_all_nodes()

    if args.site_delete:
        delete_all_sites()

    if args.skip_configure:
        log.info('Option --skip-configure was specified.')
        log.info('Skipping configuration.')
    else:
        # Call all the simple APIs (the config_file has a section for each of these)
        # So "config['SECTION']" grabs the corresponding JSON section
        for api in ['grid-details', 'passwords', 'ntp-servers', 'dns-servers', 'grid-networks']:
            gmi_api.call('PUT', api, config[api])

        site_data = create_sites(config['sites'])

        update_nodes(config['nodes'], site_data)

        print_hashed(['Configuration has finished successfully.'])

    if args.start_install:
        # Start the install
        start_and_monitor_install(True)

    else:
        print_hashed(['If you are satisfied with this configuration,',
                      'execute the script with --start-install.'])


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
        sys.stderr.write('Unable to communicate with the primary Admin Node.\n')
        sys.stderr.write('  Received: ' + str(e) + '\n')
        exit(1)
    except GmiApi.ResponseError as e:
        sys.stderr.write('Error: Received unexpected return code from the API: ' + str(e.status) + '\n')
        try:
            response = json.loads(e.data)
        except:
            # Couldn't parse JSON so just print the raw output
            sys.stderr.write(str(e.data) + '\n')
        else:
            if 'message' in response and 'text' in response['message']:
                sys.stderr.write('  ' + response['message']['text'] + '\n')
                if 'errors' in response:
                    for error in response['errors']:
                        if 'text' in error:
                            sys.stderr.write('  ' + error['text'] + '\n')
            else:
                sys.stderr.write(str(e.data) + '\n')
        exit(1)
    except AdminNotReadyError as e:
        sys.stderr.write('Error: ' + str(e) + '\n')
        exit(2)
    except AdminTimeoutError as e:
        sys.stderr.write('Error: ' + str(e) + '\n')
        exit(3)
    except NodeTimeoutError as e:
        sys.stderr.write('Error: ' + str(e) + '\n')
        exit(4)
    except DataInconsistencyError as e:
        sys.stderr.write('Error: ' + str(e) + '\n')
        exit(5)
