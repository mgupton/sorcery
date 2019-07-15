"""Alert Logic Cloud Defender Sorcery tool.
Written by: Michael Gupton
Version 0.9.3

Usage:
  sorcery phost list --api_key=<key> --dc=<dc> --cid=<cid> [--status=<status>] [--tags=<tag>]
  sorcery host purge-defunct --api_key=<key> --dc=<dc> --cid=<cid> [--age=<age>] [--tags=<tag>]
  sorcery host name-me --api_key=<key> --dc=<dc> --cid=<cid> --name=<name>
  sorcery host assign-me --api_key=<key> --dc=<dc> --cid=<cid> --policy-name=<policy-name>
  sorcery host delete-me --api_key=<key> --dc=<dc> --cid=<cid>
  sorcery host tag-me --api_key=<key> --dc=<dc> --cid=<cid> --tags=<tags>
  sorcery test --api_key=<key> --dc=<dc> --cid=<cid> [--tag=<tag>]

Options:
  --help -h            Show this help screen.
  --api_key=<key>      Alert Logic public API key.
  --dc=<dc>            Data center where the Alert Logic account is provisioned (Options: denver | ashburn | newport).
  --cid=<cid>          Alert Logic customer account.
  --status=<status>    Return only phosts/sources with the specified status [default: offline]
  --age=<age>          Number of days offline a source must be to be considered defunct [default: 7]
  --tags=<tags>        Only apply command to sources with the specified tags. (e.g. --tags="alpha,beta,gamma")
"""

#
# Written by: Michael Gupton
# Date: 2017-11-27
# Email: mgupton@alertlogic.com
#

#
# sorcery: A tool for working with Cloud Defender sources (log sources, protected hosts, hosts).
#
# This script demonstrates how to use the Cloud Defender public API for working with log sources,
# protected hosts and hosts to automate the lifecycle management of them. The term source is
# used generically to apply to sources of log data and network traffic.
#
# One of the main use cases for this script is to programmatically remove defunct hosts from the
# configuration once the underlying host instance has been terminated.
#

#
# Dependencies
#
# requests package
# docopt package

#
# Tested with Python 3.6.2.
#

#
# Usage Examples:
#
# python sorcery.py phosts list --api_key=%api_key% --dc=ashburn --cid=1234567
#

#
# The "hosts purge-defunct" will delete all log sources, phosts and hosts configurations for
# host that have been offline for 7 or more days.
#

#
# sourcery.py hosts purge-defunct --api_key=<key> --dc=<dc> --cid=<cid> --hostname=<hostname>
#

import argparse
import json
import sys
import base64
import time

import os
import re
import platform
import subprocess
from subprocess import check_output

import util

#
# Third-party packages.
# 
from docopt import docopt
import requests

#
# API endpoints
#
DC1_API_BASE_URL = "https://publicapi.alertlogic.net"
DC2_API_BASE_URL = "https://publicapi.alertlogic.com"
DC3_API_BASE_URL = "https://publicapi.alertlogic.co.uk"

API_BASE_URL = ""
SECONDS_IN_DAY = 86400
API_CALL_DELAY = 1


def main():
    
    global API_BASE_URL

    args = docopt(__doc__)

    sorcery = Sorcery(args["--api_key"], args["--dc"])

    set_dc(args["--dc"])

    if args["phost"] and args["list"]:
        phosts = get_phosts(get_encoded_api_key(args["--api_key"] + ":"), args["--cid"], args["--status"], args["--tags"])
        list_phosts(phosts)
    elif args["phost"] and args["delete"]:
        pass
    elif args["host"] and args["purge-defunct"]:
        if not args["--tags"]:
            purge_defunct_host_batches(get_encoded_api_key(args["--api_key"] + ":"), args["--cid"], int(args["--age"]), None, None)
        else:
            purge_defunct_host_batches(get_encoded_api_key(args["--api_key"] + ":"), args["--cid"], int(args["--age"]), None, args["--tags"])
    elif args["host"] and args["name-me"]:
        try:
            name_me(get_encoded_api_key(args["--api_key"] + ":"), args["--cid"], args["--name"])
        except:
            return -1
    elif args["host"] and args["assign-me"]:
        try:
            assign_me(get_encoded_api_key(args["--api_key"] + ":"), args["--cid"], args["--policy-name"])
        except Exception as e:
            return -1
    elif args["host"] and args["tag-me"]:
        try:
            tag_me(get_encoded_api_key(args["--api_key"] + ":"), args["--cid"], args["--tags"])
        except:
            return -1
    elif args["host"] and args["delete-me"]:
        pass
    elif args["test"]:
        if not args["--tag"]:
            test_purge_defunct_log_source_batches(get_encoded_api_key(args["--api_key"] + ":"), args["--cid"], None)
        else:
            test_purge_defunct_log_source_batches(get_encoded_api_key(args["--api_key"] + ":"), args["--cid"], None, args["--tags"])


def set_dc(dc):
    
    global API_BASE_URL

    if dc == "denver":
        API_BASE_URL = DC1_API_BASE_URL
    elif dc == "ashburn":
        API_BASE_URL = DC2_API_BASE_URL
    elif dc == "newport":
        API_BASE_URL = DC3_API_BASE_URL
    else:
        API_BASE_URL = None

#
# Get protected hosts with the specified status
#
# https://docs.alertlogic.com/developer/#z-sandbox/apitest/endpoint/threatmgrapi/getprotectedhostsbycriteria.htm
#
#
# If there are many protected hosts this can be an expensive and slow
# process.
#
def get_phosts(api_key, cid, status, tags):
    
    global API_BASE_URL

    BATCH_SIZE = 20
    offset = 0
    phosts = []

    while True:
        
        batch = get_phosts_batch(api_key, cid, status, BATCH_SIZE, offset, tags)

        if batch is None:
            break
        
        if len(batch) > 0:
            for phost in batch:
                phosts.append(phost)

            offset += BATCH_SIZE + 1
        else:
            return phosts


def list_phosts(phosts):
    for phost in phosts:
        print_phost(phost)


def get_phosts_batch(api_key, cid, status, batch_size, offset, tags):

    global API_BASE_URL

    api_endpoint = "/api/tm/v1/%s/protectedhosts?status.status=%s&offset=%s&limit=%s" % (cid, status, offset, batch_size)

    api_endpoint = "/api/tm/v1/%s/protectedhosts?offset=%s&limit=%s" % (cid,offset, batch_size)

    if not status is None:
        api_endpoint += "&status.status=%s" % (status)

    if not tags is None:
        api_endpoint += "&tags=%s" % (tags)

    headers = {"Accept": "application/json", "Authorization": "Basic %s" % (api_key)}

    url = API_BASE_URL + api_endpoint

    result = requests.get(url, headers=headers)

    if result.status_code == 200:
        try:
            phosts = json.loads(result.text)
            return phosts["protectedhosts"]
        except Exception:
            return None
        
#
#
#
def get_phost(api_key, cid, id):

    headers = {"Accept": "application/json", "Authorization": "Basic %s" % (api_key) }

    phosts = get_phosts(api_key, cid, None, None)

    for phost in phosts:
        
        if phost["protectedhosts"]["id"] == id:

            return phost["protectedhosts"]

    return None


#
# https://docs.alertlogic.com/developer/#z-sandbox/apitest/endpoint/threatmgrapi/deleteprotectedhost.htm
#
def delete_phost(api_key, cid, id):

    global API_BASE_URL

    headers = {"Accept": "application/json", "Authorization": "Basic %s" % (api_key)}

    api_endpoint = "/api/tm/v1/%s/protectedhosts/%s" % (cid, id)

    url = API_BASE_URL + api_endpoint

    result = requests.delete(url, headers=headers)

    if not (result.status_code >= 200 and result.status_code <= 299):
        raise Exception("Failed to delete protected hosts.")


def get_log_sources(api_key, cid, status):
    
    global API_BASE_URL

    BATCH_SIZE = 20
    offset = 0
    log_sources = []

    while True:
        
        batch = get_log_sources_batch(api_key, cid, status, BATCH_SIZE, offset, None)

        if batch is None:
            break
        
        if len(batch) > 0:
            for source in batch:
                log_sources.append(source)

            offset += BATCH_SIZE + 1
        else:
            return log_sources

#
# tags parameter is comma seperated list of values.
#
def get_log_sources_batch(api_key, cid, status, batch_size, offset, tags):
    
    global API_BASE_URL

    api_endpoint = "/api/lm/v1/%s/sources?offset=%s&limit=%s" % (cid, offset, batch_size)

    if not status is None:
        api_endpoint += "&status=%s" % (status)

    if not tags is None:
        api_endpoint += "&tags=%s" % (tags)
    
    headers = {"Accept": "application/json", "Authorization": "Basic %s" % (api_key)}

    url = API_BASE_URL + api_endpoint

    result = requests.get(url, headers=headers)

    if result.status_code == 200:
        try:
            log_sources = json.loads(result.text)
            return log_sources["sources"]
        except Exception:
            return None


def delete_log_source(api_key, cid, id):
    
    global API_BASE_URL

    headers = {"Accept": "application/json", "Authorization": "Basic %s" % (api_key)}    

    api_endpoint = "/api/lm/v1/%s/sources/%s" % (cid, id)

    url = API_BASE_URL + api_endpoint

    result = requests.delete(url, headers=headers)

    if not (result.status_code >= 200 and result.status_code <= 299):
        raise Exception("Failed to delete log source.")


def get_hosts(api_key, cid, host_type, status):

    global API_BASE_URL

    BATCH_SIZE = 20
    offset = 0
    hosts = []

    while True:
        
        batch = get_hosts_batch(api_key, cid, host_type, status, BATCH_SIZE, offset, None)

        if batch is None:
            break
        
        if len(batch) > 0:
            for host in batch:
                hosts.append(host)

            offset += BATCH_SIZE + 1
        else:
            return hosts


def get_hosts_batch(api_key, cid, type, status, batch_size, offset, tags):
    
    global API_BASE_URL
    err_msg = "Error: Unable to query hosts."

    if type.lower() == "lm":
        api_endpoint = "/api/lm/v1/%s/hosts?&offset=%s&limit=%s" % (cid, offset, batch_size)
    elif type.lower() == "tm":
        api_endpoint = "/api/tm/v1/%s/hosts?&offset=%s&limit=%s" % (cid, offset, batch_size)
    else:
        return None

    if not status is None:
        api_endpoint += "&status=%s" % (status)

    if not tags is None:
        api_endpoint += "&tags=%s" % (tags)
        
    headers = {"Accept": "application/json", "Authorization": "Basic %s" % (api_key)}

    url = API_BASE_URL + api_endpoint

    result = requests.get(url, headers=headers)

    if result.status_code == 200:
        try:
            hosts = json.loads(result.text)
            return hosts["hosts"]
        except Exception:
            print(err_msg, sys.stderr)
            return None


def delete_host(api_key, cid, host_id):
    
    err_msg = "Failed to delete to host."
    global API_BASE_URL    

    headers = {"Accept": "application/json", "Authorization": "Basic %s" % (api_key)}

    api_endpoint = "/api/tm/v1/%s/hosts/%s" % (cid, host_id)

    url = API_BASE_URL + api_endpoint

    result = requests.delete(url, headers=headers)

    if not (result.status_code >= 200 and result.status_code <= 299):
        raise Exception(err_msg)


def delete_me(api_key, cid):
    
    log_source = get_lm_source_id()

    if not log_source is None:
        delete_log_source(api_key, cid, log_source)

    phost = get_phost_id()

    if not phost is None:
        delete_phost(api_key, cid, phost)

    host = get_host_id()

    if not host is None:
        delete_host(api_key, cid, host)


def name_me(api_key, cid, name):

    Sorcery.run_mode = Sorcery.RUN_MODE_LOCAL
    err_msg = "Error naming source."

    try:

        log_source = get_lm_source_id()

        if not log_source is None:
            name_lm_source(api_key, cid, log_source, name)

        phost = get_phost_id()

        if not phost is None:
            name_phost(api_key, cid, phost, name)
    except Exception as e:
        raise Exception(err_msg)


def name_lm_source(api_key, cid, source_id, name):
    
    global API_BASE_URL
    err_msg = "Error naming log source."
        
    if util.is_windows():
        api_endpoint = "/api/lm/v1/%s/sources/eventlog/%s" % (cid, source_id)
        post_data = '{"eventlog": { "name": "%s" }}' % (name)
    
    elif util.is_linux():        
        api_endpoint = "/api/lm/v1/%s/sources/syslog/%s" % (cid, source_id)
        post_data = '{"syslog": { "name": "%s" }}' % (name)

    url = API_BASE_URL + api_endpoint

    headers = {"Content-Type": "application/json", "Accept": "application/json", "Authorization": "Basic %s" % (api_key)}

    result = requests.post(url, data=post_data, headers=headers)

    if result.status_code != 200:
        print(err_msg, file=sys.stderr)
        print(url)
        raise Exception(err_msg)


def name_lm_source_remote(api_key, cid, type, source_id, name):
    
    pass


#
# Name Log Manager sources with the host name of the source.
#
def name_lm_source_batches(api_key, cid, status, tags):
    
    global API_BASE_URL

    BATCH_SIZE = 20
    offset = 0

    Sorcery.run_mode = Sorcery.RUN_MODE_REMOTE

    while True:
        
        sources = get_log_sources_batch(api_key, cid, status, BATCH_SIZE, offset, tags)

        if sources is None:
            break
    
        if len(sources) > 0:
            for source in sources:
                for key in source.keys():
                    print_log_source(source[key])

                    #
                    # If there is hostname metadata for the source then make the source name
                    # the same as the host name.
                    #
                    if "metadata" in source[key].keys():                        
                        if "local_hostname" in source[key]["metadata"].keys():
                            if len(source[key]['metadata']['local_hostname']) > 0:
                                print("Hostnmame: %s" % (source[key]['metadata']['local_hostname']))

            offset += BATCH_SIZE

        else:
            return 


def name_phost(api_key, cid, phost_id, name):
    
    global API_BASE_URL
    err_msg = "Error naming protected host."

    api_endpoint = "/api/tm/v1/%s/protectedhosts/%s" % (cid, phost_id)

    url = API_BASE_URL + api_endpoint

    headers = {"Content-Type": "application/json", "Accept": "application/json", "Authorization": "Basic %s" % (api_key)}

    post_data = '{"protectedhost": {"name": "%s"}}' % (name)

    result = requests.post(url, data=post_data, headers=headers)

    if result.status_code != 200:
        print(err_msg, file=sys.stderr)
        print(url)
        raise Exception(err_msg)


def tag_me(api_key, cid, tags):
    
    Sorcery.run_mode = Sorcery.RUN_MODE_LOCAL
    err_msg = "Error tagging source."

    try:
        log_source = get_lm_source_id()

        if not log_source is None:
            tag_lm_source(api_key, cid, log_source, tags)

        phost = get_phost_id()

        if not phost is None:
            tag_phost(api_key, cid, phost, tags)
    except Exception as e:
        raise Exception(err_msg)


def tag_lm_source(api_key, cid, source_id, tags):
    global API_BASE_URL
    err_msg = "Error tagging log source."
        
    if util.is_windows():
        api_endpoint = "/api/lm/v1/%s/sources/eventlog/%s" % (cid, source_id)
        tags_json_text = get_tags_json(tags)
        post_data = '{"eventlog": { "tags": [%s]}}' % (tags_json_text)
    
    elif util.is_linux():        
        api_endpoint = "/api/lm/v1/%s/sources/syslog/%s" % (cid, source_id)
        tags_json_text = get_tags_json(tags)
        post_data = '{"syslog": { "tags": [%s]}}' % (tags_json_text)

    url = API_BASE_URL + api_endpoint

    headers = {"Content-Type": "application/json", "Accept": "application/json", "Authorization": "Basic %s" % (api_key)}

    result = requests.post(url, data=post_data, headers=headers)

    print("tag_lm_source: %s" % result.status_code, file=sys.stderr)

    if result.status_code != 200:
        print(err_msg, file=sys.stderr)
        print(url)
        raise Exception(err_msg)

def tag_phost(api_key, cid, phost_id, tags):
    global API_BASE_URL
    err_msg = "Error tagging protected host."

    api_endpoint = "/api/tm/v1/%s/protectedhosts/%s" % (cid, phost_id)

    url = API_BASE_URL + api_endpoint

    headers = {"Content-Type": "application/json", "Accept": "application/json", "Authorization": "Basic %s" % (api_key)}
    tags_json_text = get_tags_json(tags)

    post_data = '{"protectedhost": {"tags": [%s]}}' % tags_json_text

    result = requests.post(url, data=post_data, headers=headers)

    print("tag_phost: %s" % result.status_code, file=sys.stderr)

    if result.status_code != 200:
        print(err_msg, file=sys.stderr)
        print(url)
        raise Exception(err_msg)


def get_tags_json(tags):
    
    json_text = ""
    tags = tags.rsplit(",")

    for t in range(len(tags)):
        if t < len(tags) - 1:
            json_text += '{"name": "%s"},' % tags[t]
        else:
            json_text += '{"name": "%s"}' % tags[t]

    return json_text

#
# purge_defunct will delete any sources, phosts and hosts that have been offline for
# longer than some specified period of time.
#
# Note: Since hosts cannot be deleted if there are log sources or phosts that are configured
# for the host those must be deleted first.
#
def purge_defunct_hosts(api_key, cid, age):
    
    global SECONDS_IN_DAY

    purge_defunct_log_sources(api_key, cid, age)
    purge_defunct_phosts(api_key, cid, age)

    defunct_hosts = []

    hosts = get_hosts(api_key, cid, "lm", "offline")

    cur_time = int(time.time())

    for host in hosts:
        # The host must have been offline for the specified number of days to be considered defunct.
        if int(host["host"]["status"]["timestamp"]) <= (cur_time - (age  * SECONDS_IN_DAY)):
            defunct_hosts.append(host)

    for host in defunct_hosts:
        delete_host(api_key, cid, host["host"]["id"])
        print_host(host)
        time.sleep(1)

    return defunct_hosts


def purge_defunct_host_batches(api_key, cid, age, status, tags):
    
    global SECONDS_IN_DAY
    global API_BASE_URL

    BATCH_SIZE = 20
    offset = 0
    hosts = []

#
# To delete a host all log sources and protected
# hosts must be deleted first since they depend on
# the host configuration.
#    
    purge_defunct_log_source_batches(api_key, cid, age, status, tags)
    purge_defunct_phost_batches(api_key, cid, age, status, tags)

    cur_time = int(time.time())

#
# The loop continuously gets the first batch of hosts and deletes them.
# In this way it chomps its way through all defunct hosts.
#
    while True:
        
        batch = get_hosts_batch(api_key, cid, "lm", status, BATCH_SIZE, offset, tags)

        if batch is None:
            break
        
        if len(batch) > 0:
            for host in batch:
                if int(host["status"]["timestamp"]) <= (cur_time - (age * SECONDS_IN_DAY)):
                    hosts.append(host)
                    delete_host(api_key, cid, host["id"])
                    print_host(host)
                    time.sleep(API_CALL_DELAY)
        else:
            break

    return hosts


def print_host(host):
    print("host" + "," + host["host"]["name"] + "," + host["host"]["id"] + ","
        + str(host["host"]["status"]["timestamp"]))


def purge_defunct_log_sources(api_key, cid, age):
    
    global SECONDS_IN_DAY

    defunct_log_sources = []

    log_sources = get_log_sources(api_key, cid, "offline")

    cur_time = int(time.time())

    for log_source in log_sources:
#
# Each array element is a dictionary with a key that is the type of source (e.g. syslog, eventlog).
# So to handle each possibility the logic loops over the keys to get the key value.
#        
        for key in log_source.keys():        
            if int(log_source[key]["status"]["timestamp"]) <= (cur_time - (age * SECONDS_IN_DAY)):
                defunct_log_sources.append(log_source)

    for log_source in defunct_log_sources:
        for key in log_source.keys():
            delete_log_source(api_key, cid, log_source[key]["id"])
            print_log_source(log_source)
            time.sleep(1)

    return defunct_log_sources


def purge_defunct_log_source_batches(api_key, cid, age, status="offline", tags=None):
    global API_BASE_URL
    global API_CALL_DELAY

    BATCH_SIZE = 20
    offset = 0
    log_sources = []

    cur_time = int(time.time())

    while True:
        
        batch = get_log_sources_batch(api_key, cid, status, BATCH_SIZE, offset, tags)

        if batch is None:
            break
        
        if len(batch) > 0:
            for log_source in batch:
        #
        # Each array element is a dictionary with a key that is the type of source (e.g. syslog, eventlog).
        # So to handle each possibility the logic loops over the keys to get the key value.
        #        
                for key in log_source.keys():        
                    if int(log_source[key]["status"]["timestamp"]) <= (cur_time - (age * SECONDS_IN_DAY)):
                        log_sources.append(log_source)
                        delete_log_source(api_key, cid, log_source[key]["id"])
                        print_log_source(log_source[key])
                        time.sleep(API_CALL_DELAY)
        else:
            return log_sources


def print_log_source(source):
    print("log_source" + "," + source["name"] + "," + source["id"] + ","
        + str(source["status"]["timestamp"]))

        
def purge_defunct_phosts(api_key, cid, age):

    global SECONDS_IN_DAY

    defunct_phosts = []

    phosts = get_phosts(api_key, cid, "offline", None)

    cur_time = int(time.time())

    for phost in phosts:
        if int(phost["protectedhost"]["status"]["timestamp"]) <= (cur_time - (age * SECONDS_IN_DAY)):
            defunct_phosts.append(phost)

    for phost in defunct_phosts:
        delete_phost(api_key, cid, phost["protectedhost"]["id"])
        print_phost(phost)
        # Sleep between calls to be nice to the API service.
        time.sleep(1)

    return defunct_phosts


def purge_defunct_phost_batches(api_key, cid, age, status="offline", tags=None):
    global API_BASE_URL
    global API_CALL_DELAY

    BATCH_SIZE = 20
    offset = 0
    phosts = []

    cur_time = int(time.time())

    while True:
        
        batch = get_phosts_batch(api_key, cid, "offline", BATCH_SIZE, offset, tags)

        if batch is None:
            break
        
        if len(batch) > 0:
            for phost in batch:
                
                if int(phost["protectedhost"]["status"]["timestamp"]) <= (cur_time - (age * SECONDS_IN_DAY)):
                    delete_phost(api_key, cid, phost["protectedhost"]["id"])
                    print_phost(phost)
                    time.sleep(API_CALL_DELAY)
        else:
            return phosts


#
# Print name of protected host and date-time of the last status change.
#
def print_phosts(phosts):
    
    for phost in phosts:
        print_phost(phost)


def print_phost(phost):
    print("protectedhost" + "," + phost["protectedhost"]["name"] + "," + phost["protectedhost"]["id"] + ","
        + str(phost["protectedhost"]["status"]["timestamp"]))


def get_encoded_api_key(key):
    
    encoded = base64.b64encode(bytes(key, 'UTF-8'))

    return encoded.decode('UTF-8')


def does_source_exists():
    if get_lm_source_id() != None:
        return True
    else:
        return False

#
# This funtion only works when ran on the source host itself since it
# automagically gets the source id from the local agent config.
#
def get_lm_source_id():
    
    if not util.does_source_exec_exists():
        return None

    if util.is_windows():
        phost_exec = util.WIN_LOG_SOURCE_EXEC
    elif util.is_linux():
        phost_exec = util.LINUX_LOG_SOURCE_EXE
    else:
        return None

    cmd_output = check_output([phost_exec, "print-config"], stderr=subprocess.STDOUT)

    cmd_output = iter(cmd_output.splitlines())

    for line in cmd_output:
        
        line = line.decode('UTF-8')

        m = re.search("source_id: \"([a-fA-F0-9-]+)\"", line)

        if m != None:
            print("Found log source id: %s" % m.group(1))
            return m.group(1)

        print("No log source id found.", file=sys.stderr)

    return None


def get_phost_id():
    
    if not util.does_source_exec_exists():
        return None

    if util.is_windows():
        phost_exec = util.WIN_PHOST_EXEC
    elif util.is_linux():
        phost_exec = util.LINUX_PHOST_EXEC
    else:
        return None

    cmd_output = check_output([phost_exec, "print-config"], stderr=subprocess.STDOUT)

    cmd_output = iter(cmd_output.splitlines())

    for line in cmd_output:
        
        line = line.decode('UTF-8')

        m = re.search("source_id: \"([a-fA-F0-9-]+)\"", line)

        if m != None:
            print("Found phost id: %s" % m.group(1))
            return m.group(1)
        
        print("No phost id found.", file=sys.stderr)
    return None


def get_host_id():
    
    if not util.does_host_exec_exists():
        return None

    if util.is_windows():
        phost_exec = util.WIN_PHOST_EXEC
    elif util.is_linux():
        phost_exec = util.LINUX_PHOST_EXEC
    else:
        return None

    cmd_output = check_output([phost_exec, "print-config"], stderr=subprocess.STDOUT)

    cmd_output = iter(cmd_output.splitlines())

    for line in cmd_output:
        
        line = line.decode('UTF-8')

        m = re.search("source_id: \"([a-fA-F0-9-]+)\"", line)

        if m != None:
            print("Found host id: %s" % m.group(1))
            return m.group(1)

        print("No host id found.", file=sys.stderr)
    return None


def get_assignment_policy_id(api_key, cid, name):

    global API_BASE_URL
    err_msg = "Error getting policy id."

    api_endpoint = "/api/tm/v1/%s/policies" % (cid)

    params = {"name": name}

    url = API_BASE_URL + api_endpoint

    headers = {"Accept": "application/json", "Authorization": "Basic %s" % (api_key)}    

    try:        
        result = requests.get(url, headers=headers, params=params)

        if result.status_code == 200:
            policy = json.loads(result.text)

            return policy["policies"][0]["policy"]["id"]
        else:
            raise Exception(err_msg)
    except Exception as e:
        raise Exception(err_msg)


def assign_me(api_key, cid, policy_name):
    
    global API_BASE_URL
    err_msg = "Error assigning host."

    try:
        phost_id = get_phost_id()

        api_endpoint = "/api/tm/v1/%s/protectedhosts/" % (cid)

        policy_id = get_assignment_policy_id(api_key, cid, policy_name)

        post_data = '{"protectedhost": {"appliance": {"policy": {"id": "%s"}}}}' % (policy_id)

        api_endpoint += "%s" % (phost_id)

        url = API_BASE_URL + api_endpoint

        headers = {"Content-Type": "application/json", "Accept": "application/json", "Authorization": "Basic %s" % (api_key)}

        result = requests.post(url, data=post_data, headers=headers)

        if result.status_code != 200:
            print(err_msg, file=sys.stderr)
            print(url)
            print(result.status_code)
            print(result.text)
            raise Exception(err_msg)
    except Exception as e:
        raise Exception(err_msg)


def test_purge_defunct_log_source_batches(api_key, cid, status, tags=None):
    #lm_sources = get_log_sources(api_key, cid, "offline")
    #print(json.dumps(lm_sources))
    purge_defunct_log_source_batches(api_key, cid, 7, status, tags)
    #purge_defunct_phost_batches(api_key, cid, 7)
    #purge_defunct_host_batches(api_key, cid, 7)


class Sorcery():
#
# Some commands are ran directly on the host being configured and some
# are ran on some other host. These constants are used to define the mode.
#
    api_key = None
    RUN_MODE_LOCAL = 1
    RUN_MODE_REMOTE = 2
    run_mode = RUN_MODE_REMOTE

    def __init__(self, api_key, datacenter):
        api_key = api_key

    def name_lm_source_remote(self):
        pass


if __name__ == "__main__":
    main()
