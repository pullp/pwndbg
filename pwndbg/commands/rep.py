#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse

import gdb

import pwndbg.commands
import pwndbg.typeinfo


@pwndbg.commands.Command
def history():
    """
    show history command of this session
    """
    for cmd in pwndbg.commands.Command.history:
        print(cmd)
    

rep_cmd_parser = argparse.ArgumentParser(description='repeat history command with same keyword')
rep_cmd_parser.add_argument("keyword", type=str, help="keyword of command you want to repeat", default='')

@pwndbg.commands.ArgparsedCommand(rep_cmd_parser)
def rep(keyword=''):
    keyword = str(keyword)
    if keyword == '':
        for cmd in pwndbg.commands.Command.history:
            if not cmd or cmd == '':
                continue
            if cmd == 'rep':
                continue
            # print("execute: server "+cmd)
            gdb.execute(cmd)
            return
    else:
        for cmd in pwndbg.commands.Command.history:
            if not cmd or cmd == '':
                continue
            if cmd == 'rep':
                continue
            if keyword in cmd:
                # print("execute: server "+cmd)
                gdb.execute(cmd)
                return
    print("fail to find history command")
