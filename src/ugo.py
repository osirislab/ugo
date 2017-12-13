from idautils import *
from idc import *
from idaapi import *


def custom_cb(event, va):
    print(event, va)

class Loader(plugin_t):
    flags = PLUGIN_PROC
    comment = "Required comment"
    help = "Required help"
    wanted_name = "ugo"
    wanted_hotkey = ""

    def init(self):
        print "Loader init"
        if not init_hexrays_plugin():
            return PLUGIN_SKIP

        install_hexrays_callback(custom_cb)

        return PLUGIN_KEEP

    def term(self): # terminate
        print "Loader term"

    def run(self, arg):
        pass

# ea = BeginEA()
#
# for funcea in Functions(SegStart(ea), SegEnd(ea)):
#     print





def PLUGIN_ENTRY():
    print "Plugin entry"
    return Loader()

