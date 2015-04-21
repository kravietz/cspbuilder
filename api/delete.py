#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime
import threading

__author__ = 'Paweł Krawczyk'


def delete_all_reports_task(owner_id, db, verbose=False):
    lv = threading.local()

    lv.start_time = datetime.datetime.now(datetime.timezone.utc)

    print('delete_all_reports_thread starting for {} at {}'.format(owner_id, lv.start_time))

    lv.docs = []
    lv.i = 0
    lv.total = 0

    # cycle through all reports for this user
    for row in db.query('csp/1200_all', key=owner_id, include_docs=True):
        # skip non CSP report entries - such as KL entries
        if 'csp-report' not in row['doc']:
            continue
        # copy the document's crucial parts (id, rev), adding the _deleted flag
        lv.doc = {'_id': row['doc']['_id'], '_rev': row['doc']['_rev'], '_deleted': True}
        lv.docs.append(lv.doc)
        lv.i += 1
        lv.total += 1

        # process in batches to prevent long run-time and memory hogging
        if lv.i > 500:
            if verbose:
                print('delete_all_reports_thread deleting {}, total {}', lv.i, lv.total)
            db.save_bulk(lv.docs)
            lv.i = 0
            lv.docs = []

    # complete any remaining records
    if lv.docs:
        db.save_bulk(lv.docs)

    lv.stop_time = datetime.datetime.now(datetime.timezone.utc)

    print('delete_all_reports_thread {} completed at {}, deleted {} total'.format(owner_id, lv.stop_time, lv.total))