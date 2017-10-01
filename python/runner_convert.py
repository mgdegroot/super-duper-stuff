#!/usr/bin/env python3

import datetime
import argparse


def parse_args():
    datetime_formats=[]
    src = ''
    parser = argparse.ArgumentParser(description='Convert date time from one system to other')

    parser.add_argument('src', type=int, help='source')
    parser.add_argument('--format', type=str, choices=['format1', 'format2', 'format3'])

    args = parser.parse_args()

    if args.src:
        src = args.src

    return src


def main():
    src = parse_args()

    src_div = src / 1000.0
    src_dt = datetime.datetime.fromtimestamp(src_div)
    # dst_str = src_dt.strftime('%Y-%m-%d %H:%M:%S')
    print('{:%Y-%m-%d %H:%M:%S}'.format(src_dt))

if __name__ == '__main__':
    main()
