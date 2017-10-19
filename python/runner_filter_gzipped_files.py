#!/usr/bin/env python3
#
# Author Marcel de Groot (mg.degroot@catnipderby.nl)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import os
import sys
import gzip
import glob
import logging
import datetime
import argparse
import pprint


def filter_gzipped_files(src_glob: str, dst_dir: str, filter_str: str = "bossche-broek", resume: bool = True):
    """
    Walk all gzipped files matching <src_glob> for lines containing <filter_str> and write those
    under <dst_dir> under the same filename minus gz
    :param resume:
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

        dst_file_base = os.path.basename(src_filename)
        # remove .gz extension from destination -->
        dst_filename = os.path.join(dst_dir, dst_file_base)[:-3]

        if resume and not os.path.expanduser(dst_filename):
            try:
                with gzip.open(src_filename, "rb") as src_file:
                    print("writing to {}".format(dst_filename))
                    # when 'resume' is specified only proceed if file does not exist yet -->
                    # TODO: handle incomplete file (ie: crash in middle of file proc...
                    # if resume and not os.path.exists(dst_filename):
                    with open(dst_filename, "w") as dst_file:

                        for src_line in src_file:
                            line_cnt += 1
                            str_line = src_line.decode("utf-8")
                            if filter_str in str_line:
                                match_cnt += 1
                                dst_file.write(str_line)
            except Exception as e:
                # invalid gzip file will exit loop. Cath in broader exception handler only for these cases...
                logging.error("File '{src_filename}' not processed. Error: {err_msg}.".format(src_filename=src_filename, err_msg=e))
        else:
            logging.info("File 'src_filename' already processed. Skipping...".format(src_filename=src_filename))

    result = {
        "file_count": file_cnt,
        "line_count": line_cnt,
        "match_count": match_cnt
    }
    return result


def parse_args():
    result = {
        "src_glob": None,
        "dst_dir": None,
        "match_str": "bossche-broek",
        "logfile_base": sys.argv[0][:-3],
        "resume": True
    }

    parser = argparse.ArgumentParser()
    parser.add_argument("src_glob", type=str, help="Source location as glob (e.g. \"~/*.log.gz\")")
    parser.add_argument("dst_dir", type=str, help="Destination directory")
    parser.add_argument("--match", type=str, default=result["match_str"],
                        help="The string to match (literal, no regex yet)")
    parser.add_argument("--logfile", type=str, help="The base part of the logfile.")
    parser.add_argument("--resume", action="store_true", default=True, help="Resume an earlier session")
    parser.add_argument("--reset", action="store_true", default=False, help="Restart even when files are present")

    args = parser.parse_args()

    if args.src_glob:
        result["src_glob"] = args.src_glob
    if args.dst_dir:
        result["dst_dir"] = args.dst_dir
    if args.match:
        result["match_str"] = args.match
    if args.logfile:
        result["logfile_base"] = args.logfile
    if args.resume:
        result["resume"] = args.resume
    if args.reset:
        result["resume"] = False

    return result


if __name__ == "__main__":
    arguments = parse_args()

    start_time = datetime.datetime.now()

    logfile = "{basename}-{start_time:%Y%m%dT%H%M}.log".format(basename=arguments["logfile_base"],
                                                               start_time=start_time)
    print("Using:\n\tsrc_glob: {src_glob}\n\tdst_dir: {dst_dir}\n\tmatch_str: {match_str}"
        "\n\tresume: {resume}\n\tlogfile: {logfile}".format(
        src_glob=arguments["src_glob"],
        dst_dir=arguments["dst_dir"],
        match_str=arguments["match_str"],
        resume=arguments["resume"],
        logfile=logfile
    ))

    logging.basicConfig(filename=logfile, level=logging.INFO, format="%(asctime)s %(message)s")

    logging.info("Process started. Time is {start_time}".format(start_time=start_time))

    result = filter_gzipped_files(
        src_glob=arguments["src_glob"],
        dst_dir=arguments["dst_dir"],
        filter_str=arguments["match_str"],
        resume=arguments["resume"])

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
