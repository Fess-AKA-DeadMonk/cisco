#!/usr/bin/env python36
"""script does not verify validity of ACL
it just reverses its direction
it would not work with short port format (without `eq` or other operators)
like `access-list 101 deny icmp any 10.1.1.0 0.0.0.255 echo`
"""

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
                  'source', 'src_port', 'sub_action']
tags_no_debug = ['beginning']

ip_ptrn = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
remark_ptrn = r'.*remark (?P<remark_text>.*)'
addr_ptrn = r'host\s+' + ip_ptrn + '|' + ip_ptrn + r'\s+' + ip_ptrn + '|any'
src_ptrn = r'(?P<source>' + addr_ptrn + ')'
dst_ptrn = r'(?P<destination>' + addr_ptrn + ')'
port_ptrn = r'eq\s+\w+|' + \
    r'ge\s+\w+|' + r'le\s+\w+|' + r'range\s+\w+\s+\w+'
rule_ptrn = r'(?P<beginning>.*)' \
    + r'\s+(?P<action>permit|deny)' + r'\s+(?P<protocol>\w+)\s+' \
    + src_ptrn + r'\s+(?P<src_port>' + port_ptrn + r')?\s*' \
    + dst_ptrn + r'\s*(?P<dst_port>' + port_ptrn + r')?' \
    + r'\s*(?P<sub_action>.*)'

(remark_re, rule_re, ip_re) = list(
    map(
        lambda pattern: re.compile(pattern, re.IGNORECASE),
        (remark_ptrn, rule_ptrn, ip_ptrn)
    )
)

progress = dict([(key, 0) for key in 'rules remarks unknown total'.split()])
acl = dict((key, '') for key in 'name direction'.split())
width = max([len(tag)
             for tag in tags_rev_order if tag not in tags_no_debug]) + 1
debug_format = '{:' + str(width) + '}>{}<'
for string in acl_file:
    progress['total'] += 1
    string = string.rstrip()
    printerr("IN", string, sep='\t>')
    if progress['total'] == 1:
        match = re.match(
            r'ip access-list extended '
            + r'(?P<acl_name>\w+)(?P<acl_direction>-in|-out)?',
            string, re.IGNORECASE)
        if match:
            acl['name'] = match.group('acl_name')
            if match.group('acl_direction') == '-in':
                acl['direction'] = '-out'
            elif match.group('acl_direction') == '-out':
                acl['direction'] = '-in'
            else:
                acl['direction'] = '-rev'
            string = 'ip access-list extended ' + \
                acl['name'] + acl['direction']
            printerr("ACL\t>",
                     *[debug_format.format(field, acl[field])
                       for field in acl.keys()],
                     sep='\n\t>')
            printout(string)
            continue

    if remark_re.match(string):
        progress['remarks'] += 1
        match = remark_re.match(string)
        printerr("REMARK", match.group('remark_text'), sep='\t>')
    elif rule_re.match(string):
        progress['rules'] += 1
        match = rule_re.match(string)
        processed = match.groupdict(default='')
        printerr("RULE\t>",
                 *[debug_format.format(tag, processed[tag])
                     for tag in processed.keys() if tag not in tags_no_debug],
                 sep='\n\t>')

        string = re.sub(r'\s+', ' ',
                        ' '.join([processed[tag] for tag in tags_rev_order]))
        printerr("REV", string, sep='\t>')
    else:
        progress['unknown'] += 1
        if ip_re.match(string):
            complaint = "i don't know what it is, but it contains IP!"
        else:
            complaint = "i don't khow what it is"
        printerr("WARNING", complaint, sep='\t>')

    printout(string)

printerr(progress)
