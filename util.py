#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from apihelpers.delete import delete_all_reports_task

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

    while more_results:
        i = 0
        docs = []

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
            print('total processed=', total, 'this batch=', len(docs), 'total deleted=', deleted)
        if len(docs):
            try:
                db.delete_bulk(docs)
            except pycouchdb.exceptions.Conflict:
                pass


def kl_backup(db):
    known_list = []

    # dump known list
    for row in db.query(KL_VIEW):
        doc = db.get(row['id'])
        del doc['_rev']
        known_list.append(doc)

    filename = 'etc/known_list_backup'

    with open(filename, 'w') as file:
        json.dump(known_list, file)

    print('KL backup saved to {} with {} entries'.format(filename, len(known_list)))


def purge(db, owner_id):
    delete_all_reports_task(owner_id, db, True)


# TODO: need to port to the new multi-database approach
def dump(db, num=1000):
    items = []

    for row in db.query('reports/1200_all', limit=num):
        doc = db.get(row['id'])
        del doc['_rev']
        items.append(doc)

    filename = 'etc/dump.json'

    with open(filename, 'w') as file:
        json.dump(items, file)


def kl_restore(db, filename='etc/known_list_backup'):
    i = 0

    with open(filename) as file:
        kl_entries = json.load(file)

        for entry in kl_entries:
            try:
                db.save(entry)
            except pycouchdb.exceptions.NotFound:
                return
            i += 1

    print('Restored {} KL entries from {}'.format(i, filename))


def design_backup(db):
    ddoc = db.get('_design/csp')
    del ddoc['_rev']

    filename = 'etc/design.backup.json'

    with open(filename, 'w') as file:
        json.dump(ddoc, file)


def design_restore(db, filename='etc/design.backup.json'):
    with open(filename) as file:
        doc = json.load(file)
        db.save(doc)

        print('Restored design doc from', filename)


def init(server):
    if input("This will DELETE all reports from the database. Are you sure? yes/[no]: ") != 'yes':
        sys.exit('Init cancelled')

    try:
        db = server.database(DB)
        kl_backup(db)
        design_backup(db)
        print('Deleting database...')
        server.delete(DB)
    except pycouchdb.exceptions.NotFound:
        pass

    print('New database...')
    server.create(DB)

    # restore database connection
    db = server.database(DB)

    design_restore(db)

    try:
        kl_restore(db)
    except pycouchdb.exceptions.NotFound:
        pass


import sys

help_text = """
util.py command

Commands:

    clean: clean stale alerts
    init: reset database (preserving known list and design doc)
    purge: delete all reports for given id
    dbackup: backup design doc
    drestore: restore design doc
    kbackup: backup known list
    krestore: restore known list
    dump: dump a number of records (default: 1000)

"""

if __name__ == '__main__':

    if len(sys.argv) < 2:
        sys.exit(help_text)

    server = pycouchdb.Server(SERVER)

    cmd = sys.argv[1]

    if cmd == 'init':
        init(server)
        sys.exit(0)

    database = server.database(DB)

    if cmd == 'clean':
        for db in server:
            if db.startswith('reports_'):
                clean(db, 'debug' in sys.argv)

    elif cmd == 'kbackup':
        kl_backup(database)

    elif cmd == 'purge':
        if len(sys.argv) > 2:
            purge(database, sys.argv[2])
        else:
            print('usage: purge ID')
            sys.exit(1)

    elif cmd == 'dbackup':
        design_backup(database)

    elif cmd == 'krestore':
        kl_restore(database)

    elif cmd == 'drestore':
        design_restore(database)

    elif cmd == 'dump':
        dump(database)

    else:
        print('Bad command', cmd)
        sys.exit(1)
