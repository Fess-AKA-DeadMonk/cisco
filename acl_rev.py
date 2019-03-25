#!/usr/bin/env python36
"""script does not verify validity of ACL
it just reverses its direction"""

import re
import sys


def makeprint(file_desc):
    """returns function to print to provided file object"""
    return lambda *param, **arg: print(*param, **arg, file=file_desc)


if sys.stderr.isatty:
    printerr = makeprint(sys.stderr)
else:
    printerr = makeprint(open('/dev/null', mode='w'))


if len(sys.argv) > 1:
    file_name = sys.argv[1]
    acl_file = open(file_name)
    output_name = file_name + '.rev'
    printerr("results would be written in", output_name)
    output_file = open(output_name, mode='w')
elif sys.stdin.closed:
    printerr("no file provided and STDIN closed.",
             "can not operate without input")
    exit()
else:
    acl_file = sys.stdin
    output_file = sys.stdout
    printerr("no file specified. Reading from STDIN, writing to STDOUT")

printout = makeprint(output_file)

tags_rev_order = ['beginning', 'action', 'protocol',
                  'destination', 'dst_port',
                  'source', 'src_port']
tags_no_debug = ['beginning']

ip_ptrn = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
remark_ptrn = r'.*remark (?P<remark_text>.*)'
src_ptrn = r'(?P<source>host\s+' + ip_ptrn + '|' + \
    ip_ptrn + r'\s+' + ip_ptrn + '|any)'
dst_ptrn = r'(?P<destination>host\s+' + ip_ptrn + \
    '|' + ip_ptrn + r'\s+' + ip_ptrn + '|any)'
rule_ptrn = r'(?P<beginning>.*)' + \
    r'\s+(?P<action>permit|deny)\s+(?P<protocol>\w+)\s+' \
    + src_ptrn + r'(?P<src_port>\s+eq \w+)?\s+' \
    + dst_ptrn + r'(?P<dst_port>\s+eq \w+)?'

(remark_re, rule_re, ip_re) = list(
    map(
        lambda pattern: re.compile(pattern, re.IGNORECASE),
        (remark_ptrn, rule_ptrn, ip_ptrn)
    )
)

width = max([len(tag)
             for tag in tags_rev_order if tag not in tags_no_debug]) + 1
debug_format = '{:' + str(width) + '}>{}<'
for string in acl_file:
    string = string.rstrip()
    printerr("IN", string, sep='\t>')
    if remark_re.match(string):
        match = remark_re.match(string)
        printerr("REMARK", match.group('remark_text'), sep='\t>')
    elif rule_re.match(string):
        match = rule_re.match(string)

        processed = match.groupdict(default='')
        printerr("RULE\t>",
                 *[debug_format.format(tag, processed[tag])
                     for tag in processed.keys() if tag not in tags_no_debug],
                 sep='\n\t>')

        string = re.sub(r'\s+', ' ',
                        ' '.join([processed[tag] for tag in tags_rev_order]))
        printerr("REV", string, sep='\t>')
    elif ip_re.match(string):
        printerr(
            "WARNING", "i don't know what it is, but it contains IP!", sep='\t>')
    else:
        printerr("WARNING", "i don't khow what it is", sep='\t>')
    printout(string)
