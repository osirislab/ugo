import traceback
from idaapi import *
from idautils import *
from idc import *

import ugo

def comma_expr_tree(args):
    lexpr = None
    argc = len(args)
    if argc < 2:
        lexpr = cexpr_t(cot_helper, None)
        lexpr.helper = "a0"
        lexpr.exflags = EXFL_ALONE
    else:
        lexpr = cexpr_t(cot_comma, None)
        lexpr.exflags = EXFL_LVALUE

        descend = lexpr

        for i in range(len(args)):
            fake = cexpr_t(cot_helper, None)
            fake.exflags = EXFL_ALONE

            var_name = "a0" + str(i)

            fake.helper = var_name
            if descend._get_x() is None:
                descend._set_x(fake)
            elif descend._get_y() is None:
                descend._set_y(fake)
            else:
                ncomma = cexpr_t(cot_comma, None)
                ncomma.exflags = EXFL_ALONE

                old_right = descend._get_y()
                descend._set_y(ncomma)
                ncomma._set_x(old_right)
                ncomma._set_y(fake)
                descend = ncomma

    return lexpr

def param_fix(func_ea):
    func_struc = ugo.types.func_itabs[func_ea]
    num_params = func_struc["npcdata"]

    tif = tinfo_t()
    get_tinfo2(func_ea, tif)
    funcdata = func_type_data_t()
    tif.get_func_details(funcdata)
    new_params = ", ".join("%s %s" %(
            print_tinfo('', 0, 0, PRTYPE_1LINE, funcdata[-i].type, '', ''),
            funcdata[-i].name
        ) for i in range(num_params))


    # lol this is super jank
    func_name = GetFunctionName(func_ea).replace(".", "_")
#    go_build_comma_expr_tree()
    new_type = "void __usercall %s(%s);" %(func_name, new_params)
    
    # lol this is super jank x2
    new_type = new_type.replace("__interface_{}", "__uint64")
    SetType(func_ea, new_type)

#    print "%s -> %s" %(tif, new_type)
    num_ret = func_struc["npcdata"]

    return list(funcdata[i] for i in range(num_ret))

def funcret_fix(parent, expr, ret_values):
    if len(ret_values) == 0:
        return
    lexpr = comma_expr_tree(ret_values)
#    parent._set_x(lexpr)
#    lexpr._set_x(expr)

class func_finder(ctree_visitor_t):
    def __init__(self):
        ctree_visitor_t.__init__(self, CV_PARENTS)
        return

    def visit_insn(self, ins, *args):
        return 0

    def visit_expr(self, expr, *args):
        if expr.op == cot_call:
            func_name = GetFunctionName(expr.x.obj_ea)
            if func_name != "":
                ret_values = param_fix(expr.x.obj_ea)
                funcret_fix(self.parent_expr(), expr, ret_values)
        return 0


class hexrays_callback_info(object):
    def __init__(self):
        return None

    def event_callback(self, event, *args):
        if event == hxe_maturity:
            cfunc, maturity = args

#            if maturity == CMAT_FINAL:
            cbv = func_finder()
            cbv.apply_to(cfunc.body, None)
        return 0

def go_decomp(ea=None):
    if init_hexrays_plugin():
        GetLongPrm(INF_COMPILER).size_i = 4
        i = hexrays_callback_info()
        install_hexrays_callback(i.event_callback)

        if ea == None:
            ea = ScreenEA()

        decomp = decompile(ea)
        remove_hexrays_callback(i.event_callback)

        return decomp
    else:
        print 'Go decomp: hexrays is not available.'

