#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from couchdb import Server
__author__ = 'pawelkrawczyk'

server = Server('http://localhost:5984/')
db = server['csp']
db.compact()

for row in db.view('_all_docs', include_docs=True):
    doc = row.doc
    db.delete(doc)
