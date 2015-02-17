#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Subscribes to CouchDB feed returning any new unclassified documents and classify them in real time.
Use KnownList object that will update itself automatically on periodic basis.
"""
import sys

from api.known import KnownList
import pycouchdb

__author__ = 'Paweł Krawczyk'

database = pycouchdb.Server().database('csp')
DEBUG = False

# This object is used to classify new reports
# and periodically refreshes the KnownList
kl = KnownList(database)

print('KNOWN LIST', kl.known_list)


def callback(message, db=None):
    """
    Callback is called for each new unclassified report in the database.

    :param message:
    :param db:
    :return:
    """

    if 'id' not in message:
        if DEBUG:
            print('*****************')
            print('message=', message)
            print('==> skip, no id')
        return

    if 'deleted' in message:
        if DEBUG:
            print('*****************')
            print('message=', message)
            print('==> skip, deleted')
        return

    doc_id = message['id']
    doc = db.get(doc_id)

    if 'csp-report' not in doc:
        if DEBUG:
            print('*****************')
            print('message=', message)
            print('==> skip, no csp-report')
        return

    owner_id = doc['owner_id']
    report = doc['csp-report']

    decision = kl.decision(owner_id, report)

    review = {'decision': decision['action'], 'method': __file__, 'rule': decision['rule']}

    doc['review'] = review

    if DEBUG:
        print('*****************')
        print('message=', message)
        print('==> decision={} ({})'.format(decision['action'], decision))

    try:
        db.save(doc, batch=True)
    except pycouchdb.exceptions.Conflict as e:
        print(e, doc)

# start the main loop of the Classifier
if __name__ == '__main__':

    if len(sys.argv) > 1 and sys.argv[1] == 'debug':
        DEBUG = True

    # subscribe to the changes feed in the database and
    # run callback on each new, unclassified message
    while True:
        try:
            database.changes_feed(callback, filter='csp/unclassified')
        except ValueError:
            pass
