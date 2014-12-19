#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Subscribes to CouchDB feed returning any new Known List entries and retroactively
reclassify reports that may be impacted by the changes.
"""

from api.known import KnownList
import pycouchdb

__author__ = 'Paweł Krawczyk'

database = pycouchdb.Server().database('csp')

kl = KnownList(database, auto_update=False)


def callback(message, db=None):
    if 'id' not in message:
        return

    if 'deleted' in message:
        return

    doc_id = message['id']
    doc = db.get(doc_id)

    # update Known List with the new entry
    review_action = doc['review_action']
    review_type = doc['review_type']
    review_source = doc['review_source']
    owner_id = doc['owner_id']

    kl.add(doc['_id'], owner_id, review_type, review_source, review_action)

    # find previously unclassified entries matching these criteria
    # view returns ["732349358731880803", "img-src", "https://assets.example.com"]
    # startkey is [owner_id, review_type] because it may be a wildcard
    # so it must be matched per report
    for report in db.query('csp/1300_unknown', include_docs=True,
                           startkey=[owner_id, review_type],
                           endkey=[owner_id, review_type, {}]):

        report = report['doc']
        decision = kl.decision(owner_id, report['csp-report'])

        if decision != 'unknown':
            review = {'decision': decision['action'], 'method': __file__, 'rule': decision['rule']}
            report['review'] = review
            print('RECLASSIFY', report)
            db.save(report)


while True:
    try:
        database.changes_feed(callback, filter='csp/known_list')
    except ValueError:
        pass
