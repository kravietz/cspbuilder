#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Subscribes to CouchDB feed returning any new Known List entries and retroactively
reclassify reports that may be impacted by the changes.
"""
import sys

from api.known import KnownList
import pycouchdb

__author__ = 'Paweł Krawczyk'

database = pycouchdb.Server().database('csp')

DEBUG = False

kl = KnownList(database, auto_update=False)


def callback(message, db=None):
    if DEBUG:
        print('*****************')
        print('message=', message)

    if 'id' not in message:
        if DEBUG:
            print('==> skip, no id')
        return

    if 'deleted' in message:
        if DEBUG:
            print('==> skip, deleted')
        return

    doc_id = message['id']
    doc = db.get(doc_id)

    # update Known List with the new entry
    try:
        review_action = doc['review_action']
        review_type = doc['review_type']
        review_source = doc['review_source']
        owner_id = doc['owner_id']
    except KeyError as e:
        print('EXCEPTION document lacks key KL fields', e, doc)
        return

    # update local classifier instance with the record newly received
    # from database
    kl.add(doc['_id'], owner_id, review_type, review_source, review_action)

    # find previously unclassified entries matching these criteria
    # view returns ["732349358731880803", "img-src", "https://assets.example.com"]
    # startkey is [owner_id, review_type] because it may be a wildcard
    # so it must be matched per report
    for report in db.query('csp/1300_unknown', include_docs=True,
                           startkey=[owner_id, review_type],
                           endkey=[owner_id, review_type, {}]):

        report = report['doc']

        # check the new classification, with the KL change applied
        decision = kl.decision(owner_id, report['csp-report'])

        # check if the classifier returns a "known" answer and apply if so
        if decision['action'] != 'unknown':
            if DEBUG:
                print('==> change {} to {}'.format(report['review'], decision['action']))
                print('decision=', decision)
                print('report=', report)

            review = {'decision': decision['action'], 'method': __file__, 'rule': decision['rule']}
            report['review'] = review

            db.save(report, batch=True)
        else:
            if DEBUG:
                print('==> no change ({})'.format(decision))

# start the main loop of the Classifier
if __name__ == '__main__':

    if len(sys.argv) > 1 and sys.argv[1] == 'debug':
        DEBUG = True

    while True:
        try:
            database.changes_feed(callback, filter='csp/known_list')
        except ValueError:
            pass
