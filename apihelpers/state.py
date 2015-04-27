#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import pickle
try:
    from _pickle import UnpicklingError
except ImportError:
    UnpicklingError = KeyError

__author__ = 'Paweł Krawczyk'

"""
Class for storing classifier/retro state.
"""


class State(object):
    def __init__(self, name):
        self.state = {}
        self.name = name.replace('.py', '')
        self.state_file = os.path.join(os.getcwd(), '{}.state.dat'.format(os.path.basename(self.name)))
        self._load()

    def _load(self):
        try:
            with open(self.state_file, 'rb') as ff:
                self.state = pickle.load(ff)
        except (IOError, UnpicklingError) as e:
            self.state = {}

    def save(self):
        with open(self.state_file, 'wb') as f:
            pickle.dump(self.state, f)

