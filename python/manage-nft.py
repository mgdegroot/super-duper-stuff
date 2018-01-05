import os
import argparse
import requests
import subprocess
import re
from enum import Enum
from urllib.parse import urlparse

# URL_RULES = "http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
# URL_RULES_REVISION = "http://rules.emergingthreats.net/fwrules/FWrev"

ARGS_SRC = "FILE"
ARGS_COUNTRY_CODE = "COUNTRY_CODE"
ARGS_METHOD = "METHOD"
ARGS_FLUSH = "FLUSH"
ARGS_SUPPORTS_FLUSH = "SUPPORTS_FLUSH"
ARGS_TABLE = "TABLE"
ARGS_SET = "SET"
ARGS_UPDATE_ALL_DEFAULT = "UPDATE_ALL_DEFAULT"
ARGS_FILES_ONLY = "FILES_ONLY"
ARGS_OUTPUT_FILE = "OUTPUT_LOCATION"

TEMPL_URL_COUNTRYBLOCKS = "http://www.ipdeny.com/ipblocks/data/countries/{COUNTRY_CODE}.zone"
URL_EMERGING_THREATS = "http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
BIN_NFT = "/usr/bin/nft"
PATH_TMP = "/tmp"
# PATH_TMPFILE = "/tmp/nft_tmpset.txt"
TEST_SET = "/home/marcel/test/nft/emerging-Block-IPs.txt"

DFLT_TABLE = "inet filter"
DFLT_SET = "wan_blocks"
DFLT_FLUSH_SET = True
DFLT_OUTPUT_FILE = "/tmp/nft_tmpset.conf"


class UpdateMethod(Enum):
    ENTRY = "entry",
    FILE = "file",


def load_src(src:str):
    """
    Load a resource from a local file or uri. The result is returned as a list of lines (as is).
    :param src:
    :return: The lines in the resource as a list.
    """
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


def filter_src(raw_list:list):
    """
    Filter out unwanted lines (for now comments (#) and empty lines).
    :param raw_list:
    :return:
    """
    content_list = [x for x in raw_list if x.startswith("#") is False and x != ""]

    return content_list


def transform_src(src:list, table:str, set_name:str):
    r"""table inet filter {
            set lab_whitelist {
                    type ipv4_addr
                    elements = { 192.168.20.1, 192.168.20.5, 192.168.20.3, 192.168.20.6}
            }
    }"""
    elements = ",".join(src)

    result = """table {TABLE} {{ 
        set {SET_NAME} {{
            type ipv4_addr
            flags interval
            elements = {{{ELEMENTS}}}
        }}
    }}
""".format(TABLE=table, SET_NAME=set_name, ELEMENTS=elements)

    return result


def write_to_output(nft_set:str, tmp_file:str):
    with open(tmp_file, "w") as tmpfile:
        tmpfile.write(nft_set)


def load_nft_rules_from_file(filename:str):
    params = [BIN_NFT, "-f", filename]

    p_res = subprocess.run([*params])

    if p_res.returncode != 0:
        raise Exception("error Will Robinson")


def flush_set(table_name:str, set_name:str, set_supports_flush:bool=True):
    # nftables flush for sets is not universally available yet (ie: Debian)

    if set_supports_flush:
        params = [BIN_NFT, "flush", "set", table_name, set_name]
        p_res = subprocess.run([*params])

        if p_res.returncode != 0:
            raise Exception("error flushing set")
    else:
        legacy_recreate_set(table_name, set_name)
        # create_set(table_name, set_name)


# def create_set(table:str, set_name:str):
#     params = ["nft", "add", "set", table, set_name, "{ type ipv4_addr; flags interval;}"]
#
#     p_res = subprocess.run([*params], stderr = subprocess.PIPE)
#
#     if p_res.returncode != 0:
#         stderr = str(p_res.stderr)
#         raise ChildProcessError("no success....{ERR}".format(ERR=stderr))


def add_set_to_chain(table_name:str, chain_name:str, set_name:str):
    errors = []
    params=["nft", "add", "rule", table_name, chain_name, "ip", "saddr", "@{SET_NAME}".format(SET_NAME=set_name), "drop"]
    p_res = subprocess.run([*params], stderr=subprocess.PIPE)

    if p_res.returncode != 0:
        errors.append(str(p_res.stderr))

    return errors


def remove_set_from_chain(table_name:str, chain_name:str, set_name:str):
    # raise NotImplemented("Nog niet getest")
    errors = []

    params_gethandle=["nft", "list", "chain", table_name, chain_name, "-a"]
    p_res = subprocess.run([*params_gethandle], stdout=subprocess.PIPE, universal_newlines=True)

    stdout_str = str(p_res.stdout)
    stdout_list = stdout_str.split(sep='\n')
    regex_handle = re.compile(".*@" + set_name + ".*handle\s(\d*)") # <-- no sol / eol checks here
    handle_str = None

    for line in stdout_list:
        match_handle = regex_handle.match(line)
        if match_handle is not None:
            handle_str = match_handle.group(1)

    if handle_str is not None:
        errors.append("No matching handle found...")

    params_removeset = ["nft", "delete", "rule", table_name, chain_name, "handle", handle_str]

    p_res = subprocess.run([*params_removeset], stderr=subprocess.PIPE)
    if p_res.returncode != 0:
        errors.append(str(p_res.stderr))

    return errors


def fill_set_atomically(table_name:str, set_name:str, content_list:list):
    """
    Add elements in content_list to set set_name atomically (all or nothing).
    :param table_name:
    :param set_name:
    :param content_list:
    :return: errors as a list
    """

    errors = []
    content_str = ",".join(content_list)

    params = ["nft", "add", "element", table_name, set_name, "{{{CONTENT}}}".format(CONTENT=content_str)]

    p_res = subprocess.run([*params], stderr=subprocess.PIPE)

    if p_res.returncode != 0:
        stderr = str(p_res.stderr)
        errors.append(stderr)

    return errors


def fill_set(table_name:str, set_name:str, content_list:list):
    """
    Add elements in content_list to set set_name. If a error occurs operation continues to next element.
    :param table_name:
    :param set_name:
    :param content_list:
    :return: errors as a list
    """
    errors = []
    params = [BIN_NFT, "add", "element", table_name, set_name, "<TO_ADD>"]

    for entry in content_list:
        add_cmd = "{{{ENTRY}}}".format(ENTRY=entry)
        params[-1]= add_cmd
        p_res = subprocess.run([*params], stderr=subprocess.PIPE)

        if p_res.returncode != 0:
            stderr = str(p_res.stderr)
            errors.append("ERROR: {ENTRY}: {ERROR_MSG}\n".format(ENTRY=entry, ERROR_MSG = stderr))

    return errors


def legacy_recreate_set(table_name, set_name):
    params_create_chain = [BIN_NFT, "add", "chain", table_name, set_name]
    params_flush_chain = [BIN_NFT, "flush", "chain", table_name, set_name]
    params_del_set = [BIN_NFT, "delete", "set", table_name, set_name]
    params_create_set = [BIN_NFT, "create", "set", table_name, set_name, "{type ipv4_addr; flags interval;}"]
    params_reference_set = [BIN_NFT, "add", "rule", table_name, set_name, "ip", "saddr", "@" + set_name, "drop"]

    # create chain if not yet exists -->
    p_res = subprocess.run([*params_create_chain], stderr = subprocess.PIPE)
    if p_res.returncode != 0:
        stderr = str(p_res.stderr)
        print(stderr)

    # flush references -->
    p_res = subprocess.run([*params_flush_chain], stderr=subprocess.PIPE)
    if p_res.returncode != 0:
        stderr = str(p_res.stderr)
        print(stderr)

    # delete possible existing set -->
    p_res = subprocess.run([*params_del_set], stderr=subprocess.PIPE)
    if p_res.returncode != 0:
        stderr = str(p_res.stderr)
        print(stderr)

    # create set -->
    p_res = subprocess.run([*params_create_set], stderr=subprocess.PIPE)
    if p_res.returncode != 0:
        stderr = str(p_res.stderr)
        print(stderr)
    else:
        # if create set successful then reference set -->
        p_res = subprocess.run([*params_reference_set], stderr=subprocess.PIPE)
        if p_res.returncode != 0:
            stderr = str(p_res.stderr)
            print(stderr)


def parse_args():
    method_choices = [UpdateMethod.ENTRY.value, UpdateMethod.FILE.value]

    user_opts = {
        ARGS_SRC: URL_EMERGING_THREATS,
        ARGS_COUNTRY_CODE: None,
        ARGS_METHOD: method_choices[0],
        ARGS_FLUSH: DFLT_FLUSH_SET,
        ARGS_SUPPORTS_FLUSH: False,
        ARGS_TABLE: DFLT_TABLE,
        ARGS_SET: DFLT_SET,
        ARGS_UPDATE_ALL_DEFAULT: False,
        ARGS_FILES_ONLY: False,
        ARGS_OUTPUT_FILE: DFLT_OUTPUT_FILE,
    }

    parser = argparse.ArgumentParser()
    parser.add_argument("--src", type=str, required=False, default=user_opts[ARGS_SRC],
                        help="resource to load (URI or file path). Defaults to emerging threats."
                        )
    parser.add_argument("--block-country", type=str, required=False,
                        help="activate blocklist for country. Use two-letter country code (ru,cn, ..."
                        )
    parser.add_argument("--method", choices=method_choices, type=str, default=user_opts[ARGS_METHOD],
                        help="How to update. 'entry' will process per line and will continue after error, "
                             "'file' will use an intermediate file and update atomicaly (all or nothing)."
                        )
    parser.add_argument("--flush", action="store_true", default=user_opts[ARGS_FLUSH],
                        help="Whether or not to flush the set first"
                        )
    parser.add_argument("--supports-flush", action="store_true", default=user_opts[ARGS_SUPPORTS_FLUSH],
                        help="Older kernels do not support flush on sets. This option causes intermediate chains"
                             "being created / flushed to facilitate the updating."
                        )
    parser.add_argument("--table", type=str, default=user_opts[ARGS_TABLE],
                        help="The table of the set"
                        )
    parser.add_argument("--set", type=str, default=user_opts[ARGS_SET],
                        help="The set name to alter / update"
                        )
    parser.add_argument("--update-all-with-defaults", action="store_true", default=False)
    parser.add_argument("--files-only", action="store_true", required=False,
                        help="Just write the files that can be loaded with nft." )
    parser.add_argument("--output-file", type=str, required=False, default=user_opts[ARGS_OUTPUT_FILE],
                        help="The location to write output or temp files to.")

    args = parser.parse_args()

    # if not args.src and not args.block_country:
    #     raise ValueError("Either --src or --block-country needs to be used...")

    if args.src:
        user_opts[ARGS_SRC] = args.src
    if args.block_country:
        user_opts[ARGS_COUNTRY_CODE] = args.block_country
        user_opts[ARGS_SRC] = None
    if args.method:
        user_opts[ARGS_METHOD] = UpdateMethod(args.method)
    if args.flush:
        user_opts[ARGS_FLUSH] = args.flush
    if args.supports_flush:
        user_opts[ARGS_SUPPORTS_FLUSH] = args.supports_flush
    if args.table:
        user_opts[ARGS_TABLE] = args.table
    if args.set:
        user_opts[ARGS_SET] = args.set
    if args.update_all_with_defaults:
        user_opts[ARGS_UPDATE_ALL_DEFAULT] = args.update_all_with_defaults
    if args.files_only:
        user_opts[ARGS_FILES_ONLY] = args.files_only
    if args.output_file:
        user_opts[ARGS_OUTPUT_FILE] = args.output_file

    return user_opts


def main():
    user_opts = parse_args()

    if user_opts[ARGS_COUNTRY_CODE] is not None:
        # process country block lists -->
        url_countrylist = TEMPL_URL_COUNTRYBLOCKS.format(
            COUNTRY_CODE=user_opts[ARGS_COUNTRY_CODE]
        )

        src_lines = load_src(url_countrylist)
        src_lines = filter_src(src_lines)
        set_name = "{COUNTRY_CODE}_blocks".format(COUNTRY_CODE=user_opts[ARGS_COUNTRY_CODE])

        if user_opts[ARGS_FILES_ONLY]:
            nft_set = transform_src(src_lines, user_opts[ARGS_TABLE], set_name)
            write_to_output(nft_set, user_opts[ARGS_OUTPUT_FILE])

        elif user_opts[ARGS_METHOD] == UpdateMethod.ENTRY:
            if user_opts[ARGS_FLUSH]:
                flush_set(user_opts[ARGS_TABLE], set_name, user_opts[ARGS_SUPPORTS_FLUSH])

            errors = fill_set(user_opts[ARGS_TABLE], set_name, src_lines)

            [print(err) for err in errors]

    elif user_opts[ARGS_SRC] is not None:
        # process malware / C&C ip's / networks lists-->
        src_lines = load_src(user_opts[ARGS_SRC])
        src_lines = filter_src(src_lines)

        if user_opts[ARGS_FILES_ONLY]:
            nft_set = transform_src(src_lines, user_opts[ARGS_TABLE], user_opts[ARGS_SET])
            write_to_output(nft_set, user_opts[ARGS_OUTPUT_FILE])

        elif user_opts[ARGS_METHOD] == UpdateMethod.ENTRY:
            if user_opts[ARGS_FLUSH]:
                flush_set(user_opts[ARGS_TABLE], user_opts[ARGS_SET], user_opts[ARGS_SUPPORTS_FLUSH])

            errors = fill_set(user_opts[ARGS_TABLE], user_opts[ARGS_SET], src_lines)

            [print(err) for err in errors]

        elif user_opts[ARGS_METHOD] == UpdateMethod.FILE:
            # TODO: big sets seem to crash and not load using nft -f ...
            nft_set = transform_src(src_lines, user_opts[ARGS_TABLE], user_opts[ARGS_SET])
            write_to_output(nft_set, user_opts[ARGS_OUTPUT_FILE])
            load_nft_rules_from_file(user_opts[ARGS_OUTPUT_FILE])


if __name__ == "__main__":
    main()
