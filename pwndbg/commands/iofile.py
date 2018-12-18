#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse
import struct

import gdb
import six

import pwndbg.color.context as C
import pwndbg.color.memory as M
import pwndbg.commands
import pwndbg.typeinfo
from pwndbg.color import generateColorFunction
from pwndbg.color import message
from pwndbg.memory import readtype


print("in iofile.py")
@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def io_file(addr=None):
    """
    Prints out the IO_FILE_plus at the specified address
    """
    if addr == None:
        print("Prints out the IO_FILE_plus at the specified address")
    addr = int(addr)
    print(addr)
    gdb.execute("p/x *(struct _IO_FILE_plus *) %d"%(addr))

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def vtable(addr=None):
    """
    Prints out the vtable at the specified address
    """
    if addr == None:
        print("Prints out the vtable at the specified address")
    ptr_size = pwndbg.arch.ptrsize
    # [idx, func_name, func_addr]
    vtable = [["", "__dummy" , ""],
                ["", "__dummy2" , ""],
                ["", "__finish" , ""],
                ["", "__overflow" , ""],
                ["", "__underflow" , ""],
                ["", "__uflow" , ""],
                ["", "__pbackfail" , ""],
                ["", "__xsputn" , ""],
                ["", "__xsgetn" , ""],
                ["", "__seekoff" , ""],
                ["", "__seekpos" , ""],
                ["", "__setbuf" , ""],
                ["", "__sync" , ""],
                ["", "__doallocate" , ""],
                ["", "__read" , ""],
                ["", "__write" , ""],
                ["", "__seek" , ""],
                ["", "__close" , ""],
                ["", "__stat" , ""],
                ["", "__showmanyc" , ""],
                ["", "__imbue" , ""]]
    addr = int(addr)
    pos = addr
    ptr_type = pwndbg.typeinfo.load("int").pointer()
    for i in range(len(vtable)):
        vtable[i][0] = hex(i)
        func_ptr = readtype(ptr_type, pos)
        vtable[i][2] = hex(func_ptr)
        pos += ptr_size
    print("idx: func_name: func_addr")
    for func in vtable:
        print(message.signal(func[0])+": "+func[1]+": "+message.hint(func[2]))
    return vtable
    
