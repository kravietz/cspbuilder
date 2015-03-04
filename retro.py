#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Subscribes to CouchDB feed returning any new Known List entries and retroactively
reclassify reports that may be impacted by the changes.
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

kl = KnownList(database, auto_update=False)

from pycouchdb.feedreader import BaseFeedReader

last_seq = 0
SEQ_FILE = os.path.join(os.getcwd(), 'last_seq.txt')


def sighandler(signum, frame):
    print('Killed by signal', signum, 'saving seq', last_seq)
    with open(SEQ_FILE, 'wb') as f:
        pickle.dump(last_seq, f)
    sys.exit(0)


signal.signal(signal.SIGTERM, sighandler)
signal.signal(signal.SIGINT, sighandler)


class Reader(BaseFeedReader):
    """
    Class for processing Known List changes.
    """

    def on_message(self, message):
        global DEBUG

        if DEBUG:
            print(message)

        if 'seq' in message:
            global last_seq
            last_seq = message['seq']

        if 'id' not in message:
            return

        if 'deleted' in message:
            return

        doc_id = message['id']
        doc = self.db.get(doc_id)

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
        for result in self.db.query('csp/1300_unknown', include_docs=True,
                                    startkey=[owner_id, review_type],
                                    endkey=[owner_id, review_type, {}]):

            if not 'doc' in result:
                continue

            report = result['doc']

            if not 'csp-report' in report:
                continue

            # check the new classification, with the KL change applied
            decision = kl.decision(owner_id, report['csp-report'])

            # check if the classifier returns a "known" answer and apply if so
            if decision['action'] != 'unknown':
                if DEBUG:
                    try:
                        print('==> change {} to {}'.format(report['review'], decision['action']))
                        print('decision=', decision)
                        print('report=', report)
                    except KeyError as e:
                        print('EXCEPTION document lacks key KL fields', e, report)

                review = {'decision': decision['action'], 'method': __file__, 'rule': decision['rule']}
                report['review'] = review

                self.db.save(report, batch=True)

    def on_close(self):
        global last_seq
        with open(SEQ_FILE, 'wb') as f:
            pickle.dump(last_seq, f)


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

    # actual loop
    while True:
        try:
            database.changes_feed(Reader(), filter='csp/known_list', since=last_seq)
        except ValueError:
            pass
