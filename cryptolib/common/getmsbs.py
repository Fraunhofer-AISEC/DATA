#!/usr/bin/env python

import sys

q = eval(sys.argv[1])


def bitsize(num):
    i = 0
    shift = 1
    while num >= shift:
        i += 1
        shift <<= 1
    return i


bs = bitsize(q)
i = 0
while i < bs:
    mask = 1 << (bs - i - 1)
    if q & mask == 0:
        break
    i += 1

print(str(i))
