#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from couchdb import Server

__author__ = 'pawelkrawczyk'

server = Server('http://localhost:5984/')
db = server['csp']
db.compact()

i=0
for row in db.view('csp/_all_docs', include_docs=True):
    if 'owner_id' in row.doc:
        db.delete(row.doc)
        i += 1

print(i,'deleted')
