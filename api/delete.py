#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime
import threading

import pycouchdb


__author__ = 'Paweł Krawczyk'


def delete_all_reports_task(owner_id, db, verbose=False):
    lv = threading.local()

    lv.start_time = datetime.datetime.now(datetime.timezone.utc)

    print('delete_all_reports_thread starting for {} at {}'.format(owner_id, lv.start_time))

    lv.more_results = True
    lv.processed = 0

    while lv.more_results:
        lv.deleted = 0
        lv.docs = []
        lv.i = 0

        for row in db.query('csp/1200_all', key=owner_id, include_docs=True, limit=1000, skip=lv.processed):

            lv.processed += 1

            # skip non CSP report entries - such as KL entries
            if 'csp-report' not in row['doc']:
                continue

            # this item can be deleted, just copy the elements that are required to delete it
            lv.docs.append({'_id': row['doc']['_id'], '_rev': row['doc']['_rev']})
            lv.deleted += 1

            # i is used to see if we got any rows at all
            lv.i += 1

            if verbose:
                print('.', end='')

        # does the database still return results?
        # it's done this way because py-couchdb returns generator
        lv.more_results = lv.i > 0

        # purge this batch
        if len(lv.docs):
            if verbose:
                print('\ndelete_all_reports_thread deleting batch of {} reports'.format(len(lv.docs)))
            try:
                db.delete_bulk(lv.docs)
            except pycouchdb.exceptions.Conflict:
                pass

    lv.stop_time = datetime.datetime.now(datetime.timezone.utc)

    print('delete_all_reports_thread {} completed at {}, processed {}, deleted {}'.format(owner_id, lv.stop_time,
                                                                                          lv.processed, lv.deleted))