#     interval.py - Functions for figuring out whether numerical
#     intervals overlap, simplifying a set of intervals.
#
#     Copyright (C) 2015 Andrew J. Zimolzak <andyzimolzak@gmail.com>,
#     and licensed under GNU GPL version 3. Full notice is found in
#     the file 'LICENSE' in the same directory as this file.

from copy import deepcopy
from cryptopals import warn

def simplify(ilist):
    for i, a in enumerate(ilist):
        for j, b in enumerate(ilist):
            if i == j:
                continue
            if a[0] <= b[0] <= a[1] or a[0] <= b[1] <= a[1]:
                simplified = deepcopy(ilist)
                if i > j:
                    del simplified[i]
                    del simplified[j]
                elif i < j:
                    del simplified[j]
                    del simplified[i]
                ab = [min(a+b), max(a+b)]
                simplified.append(ab)
                return simplify(simplified)
    return ilist #no overlap if it reaches here.

L = [[1,4], [3, 10], [9, 15], [20,25], [24, 30]]
M = [[844424775573139L, 799981904840923L], [844424775573139L, 844424930131967L]]
assert simplify(L) == [[1,15], [20,30]]
assert simplify(M) == [[799981904840923L, 844424930131967L]]
warn("Passed assertions:", __file__)
