#!/usr/bin/env python3
import os
import sys
import gzip
import glob
import logging
import datetime
import argparse
import pprint


def filter_gzipped_files(src_glob:str, dst_dir:str, filter_str:str="bossche-broek"):
    """
    Walk all gzipped files matching <src_glob> for lines containing <filter_str> and write those
    under <dst_dir> under the same filename minus gz
    :param src_glob:
    :param dst_dir:
    :param filter_str:
    :return:
    """
    src_files = glob.glob(src_glob)
    file_cnt = 0
    line_cnt = 0
    match_cnt = 0

    for src_filename in src_files:
        file_cnt += 1

        with gzip.open(src_filename, "rb") as src_file:
            dst_file_base = os.path.basename(src_filename)

            # remove .gz extension from destination -->
            dst_filename = os.path.join(dst_dir, dst_file_base)[:-3]
            print("writing to {}".format(dst_filename))

            with open(dst_filename, "w") as dst_file:

                for src_line in src_file:
                    line_cnt += 1
                    str_line = src_line.decode("utf-8")
                    if filter_str in str_line:
                        match_cnt += 1
                        dst_file.write(str_line)

    result = {
        "file_count" : file_cnt,
        "line_count" : line_cnt,
        "match_count" : match_cnt
    }
    return result


def parse_args():
    result = {
        "src_glob": None,
        "dst_dir": None,
        "match_str": "bossche-broek",
        "logfile_base": sys.argv[0][:-3]
    }
    parser = argparse.ArgumentParser()
    parser.add_argument("src_glob", type=str, help="Source location as glob (e.g. ~/*.log.gz)")
    parser.add_argument("dst_dir", type=str, help="Destination directory")
    parser.add_argument("--match", type=str, default=result["match_str"],
                        help="The string to match (literal, no regex yet")
    parser.add_argument("--logfile", type=str, help="The base part of the logfile.")

    args = parser.parse_args()

    if args.src_glob:
        result["src_glob"] = args.src_glob
    if args.dst_dir:
        result["dst_dir"] = args.dst_dir
    if args.match:
        result["match_str"] = args.match
    if args.logfile:
        result["logfile_base"] = args.logfile

    return result

if __name__ == "__main__":
    arguments = parse_args()

    start_time = datetime.datetime.now()
    print(arguments["logfile_base"])
    logfile = "{basename}-{start_time:%Y%m%dT%H%M}.log".format(basename=arguments["logfile_base"], start_time=start_time)
    print("logging to {}".format(logfile))
    print("Using:\n\tsrc_glob: {src_glob}\n\tdst_dir: {dst_dir}\n\tmatch_str: {match_str}\n\tlogfile: {logfile}".format(
        src_glob=arguments["src_glob"],
        dst_dir=arguments["dst_dir"],
        match_str=arguments["match_str"],
        logfile=logfile
    ))

    logging.basicConfig(filename=logfile, level=logging.INFO, format="%(asctime)s %(message)s")

    logging.info("Process started. Time is {start_time}".format(start_time=start_time))

    src_glob = os.path.expanduser("~/test/*.log.gz")
    dst_dir = os.path.expanduser("~/test/filtered/")

    result = filter_gzipped_files(src_glob=src_glob, dst_dir=dst_dir)

    end_time = datetime.datetime.now()
    time_taken = end_time - start_time

    logging.info("Process done. Time is {endtime}".format(endtime=end_time))
    logging.info("Process duration: {duration}".format(duration=time_taken))
    logging.info("Number of files: {}".format(result["file_count"]))
    logging.info("Number of lines: {}".format(result["line_count"]))
    logging.info("Number of matches: {}".format(result["match_count"]))

    print("files: {file_cnt}\nlines: {line_cnt}\nmatches: {match_cnt}\n".format(
        file_cnt=result["file_count"],
        line_cnt=result["line_count"],
        match_cnt=result["match_count"]
    ))

