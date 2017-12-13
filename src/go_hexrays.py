from idaapi import *
from idautils import *
from idc import *


class cblock_visitor_t(ctree_visitor_t):
    def __init__(self):
        idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)

    def visit_insn(self, ins):
        return 0

    def visit_expr(self, expr):
        if expr.op != cot_call:
            return 0
        print(expr)
        return 0


class hexrays_callback_info(object):
    def __init__(self):
        return
    def event_callback(self, event, *args):
        try:
            if event == hxe_maturity:
                cfunc, maturity = args

                if maturity == idaapi.CMAT_BUILT:
                    cbv = cblock_visitor_t()
                    cbv.apply_to(cfunc.body, None)

        except:
            traceback.print_exc()

        return 0

def main():
    ea = ScreenEA()
    main_ea = None
    for function_ea in Functions(SegStart(ea), SegEnd(ea)):
        fname = GetFunctionName(function_ea)
        if fname == "main.main":
            main_ea = function_ea

    if idaapi.init_hexrays_plugin():
        i = hexrays_callback_info()
        install_hexrays_callback(i.event_callback)

main()
