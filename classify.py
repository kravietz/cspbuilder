#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Subscribes to CouchDB feed returning any new unclassified documents and classify them in real time.
Use KnownList object that will update itself automatically on periodic basis.
"""
import pickle
import sys
import signal

from api.known import KnownList
import os
import pycouchdb


__author__ = 'Paweł Krawczyk'

database = pycouchdb.Server().database('csp')
DEBUG = False

# This object is used to classify new reports
# and periodically refreshes the KnownList
kl = KnownList(database)

from pycouchdb.feedreader import BaseFeedReader

last_seq = 0
SEQ_FILE = os.path.join(os.getcwd(), 'seq_classify.txt')


def sighandler(signum, frame):
    print('Killed by signal', signum, 'saving seq', last_seq)
    with open(SEQ_FILE, 'wb') as f:
        pickle.dump(last_seq, f)
    sys.exit(0)


signal.signal(signal.SIGTERM, sighandler)
signal.signal(signal.SIGINT, sighandler)

print('Starting with Known List', kl)


class Reader(BaseFeedReader):
    """
    Class for processing Known List changes.
    """

    def on_close(self):
        global last_seq
        with open(SEQ_FILE, 'wb') as f:
            pickle.dump(last_seq, f)

    def on_message(self, message):
        global DEBUG

        if 'seq' in message:
            global last_seq
            last_seq = message['seq']

        if 'id' not in message:
            return

        if 'deleted' in message:
            return

        # fetch the actual document referenced in the update message
        doc_id = message['id']
        try:
            doc = self.db.get(doc_id)
        # the document might have been deleted in the meantime, just ignore it
        except pycouchdb.exceptions.NotFound:
            return

        # just in case (no such docs should come from the filter)
        if 'csp-report' not in doc:
            return

        owner_id = doc['owner_id']
        report = doc['csp-report']

        # obtain classifier decision based on the current Known List
        decision = kl.decision(owner_id, report)

        # update the review field
        review = {'decision': decision['action'], 'method': __file__, 'rule': decision['rule']}
        doc['review'] = review

        if DEBUG:
            print('*****************')
            print('message=', message)
            print('==> decision={} ({})'.format(decision['action'], decision))

        # finally save the classified document back to database
        try:
            self.db.save(doc, batch=True)
        except pycouchdb.exceptions.Conflict as e:
            print(e, doc)

# start the main loop of the Classifier
if __name__ == '__main__':

    if len(sys.argv) > 1 and sys.argv[1] == 'debug':
        DEBUG = True

    # read CouchDB change feed 'seq' number to avoid reading through
    # already processed changes in case of re-run
    try:
        with open(SEQ_FILE, 'rb') as ff:
            last_seq = pickle.load(ff)
    except IOError:
        seq = 0

    print('Starting with seq', last_seq)

    # subscribe to the changes feed in the database and
    # run callback on each new, unclassified message
    while True:
        try:
            database.changes_feed(Reader(), filter='csp/unclassified', since=last_seq)
        except ValueError:
            pass
