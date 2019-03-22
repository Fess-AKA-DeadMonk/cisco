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


ip_ptrn = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
remark_ptrn = r'.*remark (?P<remark_text>).*'
src_ptrn = r'(?P<source>host ' + ip_ptrn + '|' + ip_ptrn + ' ' + ip_ptrn + '|any)'
dst_ptrn = r'(?P<destination>host ' + ip_ptrn + \
    '|' + ip_ptrn + ' ' + ip_ptrn + '|any)'
rule_ptrn = r'(?P<beginning>.*) (?P<action>permit|deny) (?P<protocol>\w+) ' \
    + src_ptrn + r'(?P<src_port> eq \w+)?' + ' ' \
    + dst_ptrn + r'(?P<dst_port> eq \w+)?'

(remark_re, rule_re, ip_re) = list(
    map(
        lambda pattern: re.compile(pattern, re.IGNORECASE),
        (remark_ptrn, rule_ptrn, ip_ptrn)
    )
)
print(remark_ptrn, rule_ptrn, ip_ptrn, sep='\n\n')

for string in acl_file:
    string = string.rstrip()
    print(string)
    if remark_re.match(string):
        match = remark_re.match(string)
        print("it's a remark!", match.group('remark_text'))
    elif rule_re.match(string):
        print("it's a rule!")
    elif ip_re.match(string):
        print("i don't know what it is, but it contains IP!")
    else:
        print("i don't khow what it is")
