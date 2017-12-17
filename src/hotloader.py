from idaapi import *
from idc import *
from idautils import *

class Hotloader(plugin_t):
    flags = PLUGIN_KEEP
    comment = ""

    help = "Unloads and loads plugins"
    wanted_name = "Hotloader"
    wanted_hotkey = "Ctrl-R"

    plugins = ['test']

    def init(self):
        msg("init() called!\n")
        return PLUGIN_OK

    def run(self, arg):
        msg("run() called with %d!\n" % arg)

        for plugin in self.plugins:
            idaapi.require(plugin) # set your plugin to unload when run with -1

    def term(self):
        msg("term() called!\n")

def PLUGIN_ENTRY():
    return Hotloader()