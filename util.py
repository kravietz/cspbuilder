#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys

try:
    import ujson as json
except ImportError:
    import json

import pycouchdb


SERVER = 'http://localhost:5984/'
DB = 'csp'
CLEANUP_VIEW = 'reports/1910_stale'
KL_VIEW = 'csp/1000_known_list'


def clean(db, debug=False):
    more_results = True
    total = 0
    deleted = 0
    # updating is done in batches; views can return thousands
    # of documents, which ends up in timeouts and excessive memory usage

    try:
        for row in db.query(CLEANUP_VIEW, limit=1):
            pass
    except pycouchdb.exceptions.NotFound:
        if debug:
            print('database', db.name, 'has no', CLEANUP_VIEW, 'deleting to reinitialize')
        server.delete(db.name)
        return

    while more_results:
        i = 0
        docs = []

        if debug:
            print('Cleaning', db.name)
        for row in db.query(CLEANUP_VIEW, include_docs=True, limit=1000, skip=total):
            # if alert is not marked as archived, add it to delete list
            if 'archived' not in row['doc'] or ('archived' in row['doc'] and row['doc']['archived'] != 'true'):
                # just copy the elements that are required to delete the document
                docs.append({'_id': row['doc']['_id'], '_rev': row['doc']['_rev']})
                deleted += 1
            # total is used as offset for skip
            total += 1
            # i is used to see if we got any rows at all
            i += 1

        # does the database still return results?
        # it's done this way because py-couchdb returns generator
        more_results = i > 0
        if debug:
            print(db.name, 'total processed=', total, 'this batch=', len(docs), 'total deleted=', deleted)
        if len(docs):
            try:
                db.delete_bulk(docs)
            except pycouchdb.exceptions.Conflict:
                pass
            db.cleanup()


def dump(db):

    print('[')
    for row in db.all(include_docs=True):
        doc = db.get(row['id'])
        del doc['_rev']
        json.dump(doc, sys.stdout, ensure_ascii=False)
        print(',')
    print(']')


help_text = """
util.py command

Commands:

    clean: clean stale alerts
    dump: dump a number of records (default: 1000)

"""

if __name__ == '__main__':

    if len(sys.argv) < 2:
        sys.exit(help_text)

    server = pycouchdb.Server(SERVER)

    cmd = sys.argv[1]

    if cmd == 'clean':
        for cdb in server:
            if cdb.startswith('reports_'):
                clean(server.database(cdb), 'debug' in sys.argv)

    elif cmd == 'dump':
        dump(server.database(DB))

    else:
        print('Bad command', cmd)
        sys.exit(1)
