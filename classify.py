#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Subscribes to CouchDB feed returning any new unclassified documents and classify them in real time.
Use KnownList object that will update itself automatically on periodic basis.
"""

from api.known import KnownList
import pycouchdb

__author__ = 'Paweł Krawczyk'

database = pycouchdb.Server().database('csp')

kl = KnownList(database)

print('KNOWN LIST', kl.known_list)


def callback(message, db=None):

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

        try:
            db.save(doc)
        except pycouchdb.exceptions.Conflict as e:
            print(e, doc)


while True:
    try:
        database.changes_feed(callback, filter='csp/unclassified')
    except ValueError:
        pass
