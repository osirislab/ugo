import traceback
import idaapi
import idautils
import idc
import ugo
def param_fix(func_ea):
    func_struc = ugo.types.func_itabs[func_ea]
    num_params = func_struc["npcdata"]

    tif = idaapi.tinfo_t()
    idaapi.get_tinfo2(func_ea, tif)
    funcdata = idaapi.func_type_data_t()
    tif.get_func_details(funcdata)
    new_params = ", ".join("%s %s" %(
            idaapi.print_tinfo('', 0, 0, idaapi.PRTYPE_1LINE, funcdata[i].type, '', ''),
            funcdata[i].name
        ) for i in range(num_params))

    # lol this is super jank
    func_name = idc.GetFunctionName(func_ea).replace(".", "_")

    new_type = "void __cdecl %s(%s);" %(func_name, new_params)
    #print "%s -> %s" %(tif, new_type)
    idc.SetType(func_ea, new_type)


class cblock_visitor_t(idaapi.ctree_visitor_t):
    def __init__(self):
        idaapi.ctree_visitor_t.__init__(self, idaapi.CV_PARENTS)
        return

    def visit_insn(self, ins, *args):
        return 0

    def visit_expr(self, expr, *args):
        if expr.op == idaapi.cot_call:
            func_name = idc.GetFunctionName(expr.x.obj_ea)
            if func_name != "":
                func_struc = ugo.types.func_itabs[expr.x.obj_ea]
                num_ret_vals = func_struc["nfuncdata"]
                param_fix(expr.x.obj_ea)
        return 0



class hexrays_callback_info(object):
    def __init__(self):
        return None

    def event_callback(self, event, *args):
        if event == idaapi.hxe_maturity:
            print("callback hit")
            cfunc, maturity = args

            if maturity == idaapi.CMAT_BUILT:
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

