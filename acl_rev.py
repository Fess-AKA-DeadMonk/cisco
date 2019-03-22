#!/usr/bin/env python36
# script does not verify validity of ACL
# it just reverses its direction

import re
import sys

if len(sys.argv) > 1:
    file_name = sys.argv[1]
    acl_file = open(file_name)
    output_name = file_name + '.rev'
    print("results would be written in", output_name)
    output_file = open(output_name, mode='w')
else:
    acl_file = sys.stdin
    output_file = sys.stdout
    print("no file specified. Reading from STDIN, writing to STDOUT")

ip_ptrn = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
remark_ptrn = r'.*remark (?P<remark_text>).*'
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
print(remark_ptrn, rule_ptrn, ip_ptrn, sep='\n\n')


def makeprint(file_desc):
    """returns function to print to desired output"""
    return lambda *param, **arg: print(*param, **arg, file=file_desc)


printerr = makeprint(sys.stderr)
printout = makeprint(output_file)

for string in acl_file:
    string = string.rstrip()
    printerr(string)
    if remark_re.match(string):
        match = remark_re.match(string)
        printerr("it's a remark!", match.group('remark_text'))
    elif rule_re.match(string):
        match = rule_re.match(string)
        printerr("it's a rule!")
        processed = (match.group('beginning'), match.group('action'),
                     match.group('protocol'),
                     match.group('destination'), match.group('dst_port') or '',
                     match.group('source'), match.group('src_port') or ''
                     )
        string = re.sub(r'\s+', ' ', ' '.join(processed))
        printerr(string)
    elif ip_re.match(string):
        printerr("i don't know what it is, but it contains IP!")
    else:
        printerr("i don't khow what it is")
    printout(string)
