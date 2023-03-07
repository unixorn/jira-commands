#
# Utility functions
#
# Author: Joe Block <jblock@zscaler.com>
# License: Apache 2.0
# Copyright 2022, ZScaler Inc.


def dump_object(obj):
    """
    Dump an object for debugging

    Args:
        obj: a python object to dump
    """
    for attr in dir(obj):
        print("obj.%s = %r" % (attr, getattr(obj, attr)))
