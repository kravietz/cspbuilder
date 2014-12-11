#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json

import pycouchdb


SERVER = 'http://localhost:5984/'
DB = 'CSP'
CLEANUP_VIEW = 'csp/1910_stale'


def clean():
    server = pycouchdb.Server(SERVER)
    db = server.database(DB)

    more_results = True
    total = 0
    # updating is done in batches; views can return thousands
    # of documents, which ends up in timeouts and excessive memory usage
    while more_results:
        i = 0
        docs = []

        for row in db.query('csp/1910_stale', include_docs=True, limit=1000, skip=total):
            # if alert is not marked as archived, add it to delete list
            if 'archived' not in row['doc'] or ('archived' in row['doc'] and row['doc']['archived'] != 'true'):
                # just copy the elements that are required to delete the document
                docs.append({'_id': row['doc']['_id'], '_rev': row['doc']['_rev']})
            # total is used as offset for skip
            total += 1
            # i is used to see if we got any rows at all
            i += 1

        # does the database still return results?
        # it's done this way because py-couchdb returns generator
        more_results = i > 0
        print('i=', i, 'total=', total, 'docs=', len(docs))
        if len(docs):
            db.delete_bulk(docs)


def init():
    server = pycouchdb.Server(SERVER)
    server.delete(DB)
    server.create(DB)

    db = server.database(DB)

    with open('etc/design.json') as f:
        doc = json.load(f)
        db.save(doc)


import sys

help_text = """
util.py (clean|init)

    clean: clean stale alerts
    init: destroy database and reinit views

"""

if __name__ == '__main__':

    if len(sys.argv) < 2:
        sys.exit(help_text)

    if sys.argv[1] == 'init':
        init()

    elif sys.argv[1] == 'clean':
        clean()