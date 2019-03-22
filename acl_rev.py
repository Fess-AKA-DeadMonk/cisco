#!/usr/bin/env python36
# script does not verify validity of ACL
# it just reverses its direction

import collections
import re
import sys

# Parser = collections.namedtuple('ACLparser', ['name', 'pattern', 'parser'])


# def re_compile(pattern: str):
#     """compile case independent regex"""
#     compiled_regex = re.compile(pattern, re.IGNORECASE)
#     return compiled_regex

acl_file = sys.stdin
if len(sys.argv) > 1:
    file_name = sys.argv[1]
    acl_file = open(file_name)
else:
    print("no file specified. Reading from stdin")

for string in acl_file:
    print(string, end='')

exit

ip_ptrn = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
remark_ptrn = '.*remark .*'
src_ptrn = ' (?P<source>host ' + ip_ptrn + '|' + ip_ptrn + ip_ptrn + '|any)'
dst_ptrn = ' (?P<destination>host ' + ip_ptrn + \
    '|' + ip_ptrn + ' ' + ip_ptrn + '|any)'
rule_ptrn = '(?P<beginning>.*)(?P<action>permit|deny) (?P<protocol>\w+) ' \
    + src_ptrn + ' (?P<src_port>eq \w+ )?' \
    + dst_ptrn + ' (?P<dst_port>eq \w+ )?'

(remark_re, rule_re, ip_re) = list(
    map(
        lambda pattern: re.compile(pattern, re.IGNORECASE),
        (remark_ptrn, rule_ptrn, ip_ptrn)
    )
)
