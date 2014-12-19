#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime
import threading

__author__ = 'Paweł Krawczyk'


def cleanup_task(db):
    """
    Delete alerts that are older than 7 days. This the actual cleanup thread implementation.
    """
    print('cleanup thread starting')
    lv = threading.local()
    lv.start_time = datetime.datetime.now(datetime.timezone.utc)

    lv.results = True
    lv.total = 0
    # updating is done in batches; views can return thousands
    # of documents, which ends up in timeouts and excessive memory usage
    while lv.results:
        lv.i = 0
        lv.docs = []

        for row in db.query('csp/1910_stale', include_docs=True, limit=1000, skip=lv.total):
            # if alert is not marked as archived, add it to delete list
            if 'archived' not in row['doc'] or ('archived' in row['doc'] and row['doc']['archived'] != 'true'):
                # just copy the elements that are required to delete the document
                lv.docs.append({'_id': row['doc']['_id'], '_rev': row['doc']['_rev']})
            # total is used as offset for skip
            lv.total += 1
            # i is used to see if we got any rows at all
            lv.i += 1

        # does the database still return results?
        # it's done this way because py-couchdb returns generator
        lv.results = lv.i > 0
        print('i=', lv.i, 'total=', lv.total, 'lv.docs=', len(lv.docs))
        if len(lv.docs):
            db.delete_bulk(lv.docs)

    lv.run_time = datetime.datetime.now(datetime.timezone.utc) - lv.start_time

    print('cleanup deleted {} old reports, time {}'.format(lv.total, lv.run_time))