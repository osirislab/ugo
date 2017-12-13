from idaapi import *
from idautils import *
from idc import *

from ugo.structs import add_struct, add_struct_member

def parse_pclntab():
    runtime_pclntab = LocByName("runtime.pclntab")

    pclntab = init_pclntab_struc(runtime_pclntab)
    pclnentry = init_pclentry_struc(runtime_pclntab)
    func_itab = init_func_struc(runtime_pclntab)

    MakeStructEx(runtime_pclntab, -1, "pclntab")

    curr_ea = beginning = runtime_pclntab + 0x10
    pclntab_size = Qword(runtime_pclntab + 0x8)

    for i in range(pclntab_size):
        MakeStructEx(curr_ea, -1, "pclnentry")

        off_ea = curr_ea + 0x8
        func_itab_loc = runtime_pclntab + Qword(off_ea)
        MakeStructEx(func_itab_loc, -1, "_func_itab")

        curr_ea += 0x10

def init_pclntab_struc(runtime_pclntab):
    struct_name = "pclntab"
    sid = GetStrucIdByName(struct_name)
    if sid != BADADDR:
        DelStruc(sid)
    sid = add_struct(struct_name)
    err = add_struct_member(sid, "_magic", field_size=4) # this is how to do pointers
    err = add_struct_member(sid, "something", field_size=4)
    err = add_struct_member(sid, "numPclnentries")

    return sid

def init_pclentry_struc(runtime_pclntab):
    struct_name = "pclnentry"
    sid = GetStrucIdByName(struct_name)
    if sid != BADADDR:
        DelStruc(sid)
    sid = add_struct(struct_name)
    err = add_struct_member(sid, "function", flags=(FF_0OFF | FF_QWORD)) # this is how to do pointers
    err = add_struct_member(sid, "dataOff", flags=(FF_0OFF | FF_QWORD), metadata=runtime_pclntab)

    return sid

def init_func_struc(runtime_pclntab):
    struct_name = "_func_itab"
    sid = GetStrucIdByName(struct_name)
    if sid != BADADDR:
        DelStruc(sid)
    sid = add_struct(struct_name)
    err = add_struct_member(sid, "entry", flags=(FF_0OFF | FF_QWORD))
    err = add_struct_member(sid, "nameOff", field_size=4, flags=(FF_0OFF | FF_DWORD), metadata=runtime_pclntab)
    err = add_struct_member(sid, "argSize", field_size=4)
    err = add_struct_member(sid, "_", field_size=4)
    err = add_struct_member(sid, "pcsp", flags=(FF_0OFF | FF_DWORD), metadata=runtime_pclntab)
    err = add_struct_member(sid, "pcfile", flags=(FF_0OFF | FF_DWORD), metadata=runtime_pclntab)
    err = add_struct_member(sid, "pcln", field_size=4)
    err = add_struct_member(sid, "npcdata", field_size=4)
    err = add_struct_member(sid, "nfuncdata", field_size=4)

    return sid

class myplugin_t(idaapi.plugin_t):
    flags = PLUGIN_KEEP
    comment = "This is a comment"

    help = "This is help"
    wanted_name = "My Python plugin"
    wanted_hotkey = "Alt-F8"

    def init(self):
        idaapi.msg("init() called!\n")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        idaapi.msg("run() called with %d!\n" % arg)
        parse_pclntab()


    def term(self):
        idaapi.msg("term() called!\n")

def PLUGIN_ENTRY():
    return myplugin_t()


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