#!/usr/bin/env python3
#
# Utility functions
#
# Author: Joe Block <jblock@zscaler.com>
# License: Apache 2.0
# Copyright 2022, ZScaler Inc.


def dump_object(obj):
    """
    Dump an object for debugging
    """
    for attr in dir(obj):
        print("obj.%s = %r" % (attr, getattr(obj, attr)))
