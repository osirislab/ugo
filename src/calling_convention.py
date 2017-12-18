import traceback
import idaapi
import idautils
import idc
import ugo

class cblock_visitor_t(idaapi.ctree_visitor_t):
    def __init__(self):
        idaapi.ctree_visitor_t.__init__(self, idaapi.CV_PARENTS)
        return

    def visit_insn(self, ins, *args):
        return 0

    def visit_expr(self, expr, *args):
        if expr.op == idaapi.cot_call:
            func_struc = ugo.structs.load_struct(expr.x.obj_ea, "_func_itab")
#            function_name = idc.GetFunctionName(expr.x.obj_ea)
            function_name = GetFunctionName(expr.x.obj_ea)
            print(function_name, func_struc)
            print("alist", list(expr.a))
        return 0



class hexrays_callback_info(object):
    def __init__(self):
        return None

    def event_callback(self, event, *args):
        if event == idaapi.hxe_maturity:
            print("callback hit")
            cfunc, maturity = args

            if maturity == idaapi.CMAT_FINAL:
                cbv = cblock_visitor_t()
                cbv.apply_to(cfunc.body, None)
        
        return 0

def go_decomp(ea=None):
    if idaapi.init_hexrays_plugin():
        idc.GetLongPrm(idc.INF_COMPILER).size_i = 4
        i = hexrays_callback_info()
        idaapi.install_hexrays_callback(i.event_callback)

        if ea == None:
            ea = idc.ScreenEA()
        decomp = idaapi.decompile(ea)
        idaapi.remove_hexrays_callback(i.event_callback)

        return decomp
    else:
        print 'Go decomp: hexrays is not available.'

