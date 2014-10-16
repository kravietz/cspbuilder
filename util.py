#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pycouchdb

server = pycouchdb.Server('http://localhost:5984/')
db = server.database('csp')

for row in db.query('csp/1910_week_old', include_docs=True, limit=10):
    print(row)

exit()

results=True
total=0
owner='6578275293912231771'
directive='script-src'
while results:
    i = 0
    docs = []
    for row in db.query('csp/1300_unknown', include_docs=True, limit=1000, startkey=[owner, directive, 'self'], endkey=[owner,directive,{}], skip=total):
        docs.append({ '_id': row['doc']['_id'], '_rev': row['doc']['_rev']})
        i += 1
        total += 1
    results = i > 0
    print(i, total)
    if len(docs):
        db.delete_bulk(docs)

print(total,'deleted')
db.compact()
