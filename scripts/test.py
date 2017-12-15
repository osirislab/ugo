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


def get_non_funcs():
    for i in xrange(idaapi.get_nlist_size()):
        ea   = idaapi.get_nlist_ea(i)
        name = idaapi.get_nlist_name(i)
        if not idaapi.get_func(ea) and Dword(ea) != 0 and Dword(ea) != 4294967295 and 'unicode' not in name:
            yield (ea, name, Dword(ea))


print(len(list(get_non_funcs())))

def pp(s):
    print s

map(pp, get_non_funcs())



