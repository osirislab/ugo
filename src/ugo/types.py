from .structs import *
from .store import Store

pclnentries = Store()
ENTRY_LOADED = False

def parse_pclntab():
    runtime_pclntab = LocByName("runtime.pclntab")

    pclntab = init_pclntab_struc(runtime_pclntab)
    pclnentry = init_pclentry_struc(runtime_pclntab)
    func_itab = init_func_struc(runtime_pclntab)

    MakeStructEx(runtime_pclntab, -1, "pclntab")

    curr_ea = beginning = runtime_pclntab + 0x10
    pclntab_size = Qword(runtime_pclntab + 0x8)

    for i in range(pclntab_size):
        # MakeStructEx(curr_ea, -1, "pclnentry")
        SetType(curr_ea, "pclnentry")

        off_ea = curr_ea + 0x8
        func_itab_loc = runtime_pclntab + Qword(off_ea)
        succ = SetType(func_itab_loc, "_func_itab")
        if succ:
            pclnentries[func_itab_loc] = ENTRY_LOADED
        # MakeStructEx(func_itab_loc, -1, "_func_itab")

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
    err = add_struct_member(sid, "function", flags=(FF_0OFF | FF_QWRD)) # this is how to do pointers
    err = add_struct_member(sid, "dataOff", flags=(FF_0OFF | FF_QWRD), metadata=runtime_pclntab)

    return sid



def init_func_struc(runtime_pclntab):
    struct_name = "_func_itab"
    sid = GetStrucIdByName(struct_name)
    if sid != BADADDR:
        DelStruc(sid)
    sid = add_struct(struct_name)
    err = add_struct_member(sid, "entry", flags=(FF_0OFF | FF_QWRD))
    err = add_struct_member(sid, "nameOff", field_size=4, flags=(FF_0OFF | FF_DWRD), metadata=runtime_pclntab)
    err = add_struct_member(sid, "argSize", field_size=4)
    err = add_struct_member(sid, "_", field_size=4)
    err = add_struct_member(sid, "pcsp", field_size=4, flags=(FF_0OFF | FF_DWRD), metadata=runtime_pclntab)
    err = add_struct_member(sid, "pcfile", field_size=4, flags=(FF_0OFF | FF_DWRD), metadata=runtime_pclntab)
    err = add_struct_member(sid, "pcln", field_size=4) # program counter to line number
    err = add_struct_member(sid, "npcdata", field_size=4)
    err = add_struct_member(sid, "nfuncdata", field_size=4)

    return sid