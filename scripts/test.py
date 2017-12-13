from idautils import *
from idc import *
from idaapi import *

ea = BeginEA()

output = open('output', 'w')

output.write('Lists Functions\n')


for funcea in Functions(SegStart(ea), SegEnd(ea)):
    output.write(GetFunctionName(funcea) + '\n')

output.close()

idc.Exit(0)


