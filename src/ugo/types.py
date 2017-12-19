from .structs import *
from .store import Store

func_itabs = Store()
ENTRY_LOADED = False

def parse_pclntab(runtime_pclntab):

    pclntab = init_pclntab_struc(runtime_pclntab)
    pclnentry = init_pclentry_struc(runtime_pclntab)
    func_itab = init_func_struc(runtime_pclntab)

    MakeStructEx(runtime_pclntab, -1, "pclntab")

    curr_ea = beginning = runtime_pclntab + 0x10
    pclntab_size = Qword(runtime_pclntab + 0x8)

    for i in range(pclntab_size):
        # MakeStructEx(curr_ea, -1, "pclnentry")
        SetType(curr_ea, "pclnentry")

        pclnentry = load_struct(curr_ea, 'pclnentry')

        func_itab_loc = runtime_pclntab + pclnentry['dataOff']
        succ = SetType(func_itab_loc, "_func_itab")

        if succ:
            func_itabs[pclnentry['function']] = load_struct(func_itab_loc, '_func_itab')
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

'''
// Layout of in-memory per-function information prepared by linker
// See https://golang.org/s/go12symtab.
// Keep in sync with linker (../cmd/link/internal/ld/pcln.go:/pclntab)
// and with package debug/gosym and with symtab.go in package runtime.
type _func struct {
	entry   uintptr // start pc
	nameoff int32   // function name

	args int32 // in/out args size (literally offset from rsp where rets + args ends - leon)
	_    int32 // previously legacy frame size; kept for layout compatibility

	pcsp      int32
	pcfile    int32
	pcln      int32
	npcdata   int32
	nfuncdata int32
}
'''