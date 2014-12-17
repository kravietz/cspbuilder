#!/usr/bin/env python
# -*- coding: utf-8 -*-
from api.known import KnownList
import pycouchdb

__author__ = 'Paweł Krawczyk'

database = pycouchdb.Server().database('csp_test')

kl = KnownList(database)


def callback(message, db=None):
    print(message)

    if 'id' not in message:
        return

    if 'deleted' in message:
        return

    doc_id = message['id']
    doc = db.get(doc_id)

    if 'csp-report' in doc:
        owner_id = doc['owner_id']
        report = doc['csp-report']
        decision = kl.decision(owner_id, report)

        review = {'decision': decision['action'], 'method': __file__, 'rule': decision['rule']}

        doc['review'] = review

        print('CLASSIFIED', doc)

        db.save(doc)


while True:
    try:
        database.changes_feed(callback, filter='csp/unclassified')
    except ValueError:
        pass