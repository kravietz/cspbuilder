#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

import pycouchdb


server = pycouchdb.Server('http://localhost:5984/')
server.create('csp')

db = server.database('csp')

with open('etc/design.json') as f:
    doc = json.load(f)
    db.save(doc)

exit()
