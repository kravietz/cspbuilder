#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Subscribes to CouchDB feed returning any new Known List entries and retroactively
reclassify reports that may be impacted by the changes.
"""

from api.known import KnownList
import pycouchdb

__author__ = 'Paweł Krawczyk'

database = pycouchdb.Server().database('csp_test')

kl = KnownList(database, auto_update=False)


def callback(message, db=None):
    if 'id' not in message:
        return

    if 'deleted' in message:
        return

    doc_id = message['id']
    doc = db.get(doc_id)

    print(message, doc)

    # {'_id': 'ca444ca84a1d4b09a7e88e72b31937d4', 'review_source': "'unsafe-inline'",
    # 'review_action': 'accept', 'review_type': 'script-src',
    # '_rev': '1-bb255fee11381c8522ad0d8c1f6b1471', 'owner_id': '732349358731880803'}

    review_action = doc['review_action']
    review_type = doc['review_type']
    review_source = doc['review_source']

    for report in db.query('csp/1300_unknown', include_docs=True):


# if 'csp-report' in doc:
# owner_id = doc['owner_id']
#     report = doc['csp-report']
#     decision = kl.decision(owner_id, report)
#
#     review = {'decision': decision['action'], 'method': __file__, 'rule': decision['rule']}
#
#     doc['review'] = review
#
#     print('CLASSIFIED', doc)
#
#     db.save(doc)


while True:
    try:
        database.changes_feed(callback, filter='csp/known_list')
    except ValueError:
        pass
