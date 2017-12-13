import idc

print "Hello World!"

with open('output', 'a') as f:
    f.write("Hello World!")

"""
The purpose of this file is to test that your IDA installation is working
correctly from the ground up.
Hello World! is the only thing you should see in your "Output Window" at the
bottom of the IDAPro GUI
"""

idc.Exit(0)