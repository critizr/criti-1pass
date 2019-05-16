#!/usr/bin/env python
# -*- coding: utf-8 -*-

import random


def is_unlock(f):
    def wrapper(*args, **kwargs):
        if args[0]._locked:
            raise ValueError(u"You need to call `unlock` methods first")
        return f(*args, **kwargs)
    return wrapper


def gen_random_string(char_set, length):
    if not hasattr(gen_random_string, "rng"):
        gen_random_string.rng = random.SystemRandom()
    return u''.join([gen_random_string.rng.choice(char_set) for _ in xrange(length)])
