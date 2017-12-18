import idaapi
import idautils
import idc

#class cblock_visitor_t(idaapi.ctree_visitor_t):
#    def __init__(self):
#        idaapi.ctree_visitor_t.__init__(self, idaapi.CV_PARENTS)
#        return
#
#    def visit_insn(self, ins):
#        return 0
#
#    def visit_expr(self, expr):
#        if expr.op != idaapi.cot_call:
#            print(expr)
#            print(dir(expr))
#            return 0
#
#        return 0

class hexrays_callback_info(object):
    def __init__(self):
        return None

    def event_callback(self, event, *args):
        print("callback hit")
        try:
            print(event)
            if event == idaapi.hxe_maturity:
                cfunc, maturity = args
                print("callback here")

                if maturity == idaapi.CMAT_BUILT:
                    print("cfunc", cfunc)
                    print("cfuncbody", cfunc.body)
#                    cbv = cblock_visitor_t()
#                    cbv.apply_to(cfunc.body, None)

        except:
            print("wtf")
            traceback.print_exc()
        
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

