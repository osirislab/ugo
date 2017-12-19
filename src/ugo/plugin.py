from idaapi import *
from idc import *
from idautils import *

from .structs import *
from .types import *

class Ugo(plugin_t):
    flags = PLUGIN_OK
    comment = ""

    help = "Go Decompilation Plugin"
    wanted_name = "UGo"
    wanted_hotkey = "F8"

    def init(self):
        msg("init() called!\n")
        return PLUGIN_OK

    def run(self, arg):
        if arg == 1:
            flags |= PLUGIN_UNL
        msg("run() called with %d!\n" % arg)
        GetLongPrm(INF_COMPILER).size_i = 4 # go binaries set int size to 4

        runtime_pclntab = get_segm_by_name("runtime.pclntab")
        if not runtime_pclntab:
            runtime_pclntab = get_segm_by_name('.gopclntab')
        if not runtime_pclntab:
            runtime_pclntab = get_segm_by_name('__gopclntab')

        parse_pclntab(runtime_pclntab.start_ea)

    def term(self):
        msg("term() called!\n")

def PLUGIN_ENTRY():
    return Ugo()

