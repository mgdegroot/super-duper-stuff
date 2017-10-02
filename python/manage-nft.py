#!/usr/bin/env python3
import os
import requests
import subprocess
import argparse
import pprint
from enum import Enum
from urllib.parse import urlparse


def load_src(src:str):
    url = urlparse(src)

    if url.scheme is not None and url.scheme != "":
        raw_list = load_from_url(src)
    else:
        raw_list = load_from_file(src)

    return raw_list


def load_from_file(full_path:str):
    if not os.path.exists(full_path):
        raise FileNotFoundError('File {src_filename} not found...'.format(src_filename=full_path))

    with open(full_path) as src_file:
        raw = src_file.read()
    raw_list = raw.splitlines()

    return raw_list


def load_from_url(url:str):
    response = requests.get(url)
    response.raise_for_status()

    raw = response.text

    raw_list = raw.splitlines()

    return raw_list


def filter_raw(raw_list:list):
    content_list = [x for x in raw_list if x.startswith("#") == False and x != ""]
    for i in content_list:
        print(i)

    return content_list


def nft_create_set(set_name:str, table:str):
    params = ["nft", "add", "set", table, set_name, "{ type ipv4_addr; flags interval;}"]

    p_res = subprocess.run([*params])

    if p_res.returncode == 0:
        print('success')
    else:
        raise ChildProcessError("no success....")


def nft_add_to_set(set_name:str, table:str, content_list:list):
    content_str = ",".join(content_list)

    params = ["nft", "add", "element", table, set_name, "{{{content}}}".format(content=content_str)]

    p_res = subprocess.run([*params])

    if p_res.returncode == 0:
        print('success')
    else:
        raise ChildProcessError("no success....")


def nft_add_set_to_chain(set_name:str, table:str, chain:str):
    params=["nft", "add", "rule", table, chain, "ip", "saddr", "@{set_name}".format(set_name=set_name), "drop"]
    p_res = subprocess.run([*params])

    if p_res.returncode == 0:
        print('success')
    else:
        raise ChildProcessError("no success....")


def parse_args():
    action_choices = ["status", "refresh", "load", "start", "stop", "just-do-it-already"]

    user_opts = {
        "ACTION": action_choices[0] ,
        "SRC": "/home/blaatenator/test/emerging-Block-IPs.txt",
        # "SRC": "http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
        "TABLE": "inet filter",
        "CHAIN": "input",
        "SET_NAME": "wan_blocks",
    }

    parser = argparse.ArgumentParser()

    parser.add_argument("action", choices=action_choices, type=str,
                        help="What to do")
    parser.add_argument("--src", default=user_opts["SRC"], type=str,
                        help="Where to fetch the blocklist from")
    parser.add_argument('--table', default=user_opts["TABLE"], type=str,
                        help="What NF table to use")
    parser.add_argument('--chain', default=user_opts["CHAIN"], type=str,
                        help="What chain to use")
    parser.add_argument("--set-name", dest="set_name", default=user_opts["SET_NAME"], type=str,
                        help="The name of the ip / network set")

    args = parser.parse_args()

    if args.action:
        user_opts["ACTION"] = args.action
    if args.src:
        user_opts["SRC"] = args.src
    if args.table:
        user_opts["TABLE"] = args.table
    if args.chain:
        user_opts["CHAIN"] = args.chain
    if args.set_name:
        user_opts["SET_NAME"] = args.set_name

    return user_opts


class Action(Enum):
    REFRESH = 1,
    STATUS = 2


def main():
    # URL_RULES = "http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
    URL_RULES_REVISION = "http://rules.emergingthreats.net/fwrules/FWrev"
    # SET_NAME="wan_blocks"
    # TABLE_NAME="inet filter"
    # CHAIN_NAME="input"

    user_opts = parse_args()
    steps_to_perform = []

    if user_opts["ACTION"] == "just-do-it-already":
        # steps_to_perform = [1,2,3,4,5]
        raw_list = load_src(user_opts["SRC"])
        content_list = filter_raw(raw_list)

        nft_create_set(set_name=user_opts["SET_NAME"], table=user_opts["TABLE"])
        nft_add_to_set(set_name=user_opts["SET_NAME"], table=user_opts["TABLE"], content_list=content_list)
        nft_add_set_to_chain(set_name=user_opts["SET_NAME"], table=user_opts["TABLE"], chain=user_opts["CHAIN"])
    if user_opts["ACTION"] == "load":
        # fetch list, parse, load in nftables but do not activate (reference) in chain yet
        raw_list = load_src(user_opts["SRC"])
        content_list = filter_raw(raw_list)

        nft_create_set(set_name=user_opts["SET_NAME"], table=user_opts["TABLE"])
        nft_add_to_set(set_name=user_opts["SET_NAME"], table=user_opts["TABLE"], content_list=content_list)

    elif user_opts["ACTION"] == "start":
        # set already loaded in nftables
        # reference the set in a table-chain
        nft_add_set_to_chain(set_name=user_opts["SET_NAME"], table=user_opts["TABLE"], chain=user_opts["CHAIN"])


    # if 1 in steps_to_perform:
    #

    # src_filename = os.path.expanduser('/home/blaatenator/test/emerging-Block-IPs.txt')
    #
    # raw_list = load_from_file(src_filename)
    # # raw_list = load_from_url(URL_RULES)
    #
    # content_list = filter_raw(raw_list)


if __name__ == '__main__':
    main()