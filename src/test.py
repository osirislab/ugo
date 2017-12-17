from idaapi import *
from idautils import *
from idc import *

import ugo

def PLUGIN_ENTRY():
    return ugo.PLUGIN_ENTRY()

"""
def MakeStructEx(ea, size, strname):
    \"""
    Convert the current item to a structure instance

    @param ea: linear address
    @param size: structure size in bytes. -1 means that the size
        will be calculated automatically
    @param strname: name of a structure type

    @return: 1-ok, 0-failure
    \"""
    strid = idaapi.get_struc_id(strname)

    if size == -1:
        size = idaapi.get_struc_size(strid)

    return idaapi.doStruct(ea, size, strid)
"""

# if(arg == -1)
# {
#     PLUGIN.flags |= PLUGIN_UNL;
# }