#!/usr/bin/env python3
import os
import requests
import subprocess


def load_from_file(full_path:str):
    if not os.path.exists(full_path):
        raise FileNotFoundError('File {src_filename} not found...'.format(src_filename=full_path))

    with open(full_path) as src_file:
        raw = src_file.read()
    raw_list = raw.splitlines()

    return raw_list


def load_from_url(url):
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


def main():
    URL_RULES = 'http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt'
    URL_RULES_REVISION = 'http://rules.emergingthreats.net/fwrules/FWrev'
    SET_NAME="wan_blocks"
    TABLE_NAME="inet filter"
    CHAIN_NAME="input"

    src_filename = os.path.expanduser('/home/blaatenator/test/emerging-Block-IPs.txt')

    raw_list = load_from_file(src_filename)
    # raw_list = load_from_url(URL_RULES)

    content_list = filter_raw(raw_list)
    nft_create_set(set_name=SET_NAME, table=TABLE_NAME)
    nft_add_to_set(set_name=SET_NAME, table=TABLE_NAME, content_list=content_list)
    nft_add_set_to_chain(set_name=SET_NAME, table=TABLE_NAME, chain=CHAIN_NAME)


if __name__ == '__main__':
    main()