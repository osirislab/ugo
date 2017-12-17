from idaapi import *
from idc import *
from idautils import *

from .structs import *
from .types import *

class Ugo(plugin_t):
    flags = PLUGIN_OK
    comment = ""

    help = "Go Decompilation Plugin"
    wanted_name = "Ugo"
    wanted_hotkey = "F8"

    def init(self):
        msg("init() called!\n")
        return PLUGIN_OK

    def run(self, arg):
        if arg == 1:
            flags |= PLUGIN_UNL
        msg("run() called with %d!\n" % arg)
        GetLongPrm(INF_COMPILER).size_i = 4 # go binaries set int size to 4

        parse_pclntab()

    def term(self):
        msg("term() called!\n")

def PLUGIN_ENTRY():
    return Ugo()

'''
// Layout of in-memory per-function information prepared by linker
// See https://golang.org/s/go12symtab.
// Keep in sync with linker (../cmd/link/internal/ld/pcln.go:/pclntab)
// and with package debug/gosym and with symtab.go in package runtime.
type _func struct {
	entry   uintptr // start pc
	nameoff int32   // function name

	args int32 // in/out args size
	_    int32 // previously legacy frame size; kept for layout compatibility

	pcsp      int32
	pcfile    int32
	pcln      int32
	npcdata   int32
	nfuncdata int32
}
'''