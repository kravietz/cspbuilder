#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from couchdb import Server
__author__ = 'pawelkrawczyk'

server = Server('http://new.cspbuilder.info:8080')
db = server['csp']

for row in db.view('_all_docs'):
    print(row)