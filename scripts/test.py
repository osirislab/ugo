from idautils import *
from idc import *
from idaapi import *

# ea = BeginEA()
#
# output = open('output', 'w')
#
# output.write('Lists Functions\n')
#
#
# for funcea in Functions(SegStart(ea), SegEnd(ea)):
#     output.write(GetFunctionName(funcea) + '\n')
#
# output.close()


# def get_non_funcs():
#     for i in xrange(idaapi.get_nlist_size()):
#         ea   = idaapi.get_nlist_ea(i)
#         name = idaapi.get_nlist_name(i)
#         if not idaapi.get_func(ea) and Dword(ea) != 0 and Dword(ea) != 4294967295 and 'unicode' not in name:
#             yield (ea, name, Dword(ea))
#
#
# print(len(list(get_non_funcs())))
#
# def pp(s):
#     print s
#
# map(pp, get_non_funcs())

from ugo.structs import struct_members

for m in struct_members('pclnentry'):
    print(dir(m))

# count = 0
# for ea, name in Names():
#     if get_func(ea):
#         continue
#
#     if 'unicode' in name:
#         continue
#
#     if Qword(ea) == 0 or Qword(ea) == 18446744073709551615:
#         continue
#
#
#     print(hex(ea) + ': ' + name, Qword(ea))
#     count += 1
#
# print('Discovered ' + str(count) + ' results')





