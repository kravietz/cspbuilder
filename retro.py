#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Subscribes to CouchDB feed returning any new Known List entries and retroactively
reclassify reports that may be impacted by the changes.
"""
import pickle
import sys
import signal
import os

import pycouchdb
from pycouchdb.feedreader import BaseFeedReader

from apihelpers.known import KnownList
from apihelpers.utils import get_reports_db


__author__ = 'Paweł Krawczyk'

server = pycouchdb.Server()

DEBUG = False
if 'debug' in sys.argv:
    DEBUG = True

# this is where Known List is stored
DB_NAME = 'csp'

state_table = {}

kl = KnownList(server.database(DB_NAME), auto_update=False)
if DEBUG:
    print(kl)

# read CouchDB change feed 'seq' number to avoid reading through
# already processed changes in case of re-run
STATE_FILE = os.path.join(os.getcwd(), '{}.state.dat'.format(os.path.basename(__name__)))
from _pickle import UnpicklingError

try:
    with open(STATE_FILE, 'rb') as ff:
        state_table = pickle.load(ff)
except (IOError, UnpicklingError) as e:
    print('Warning: cannot restore state table', e)
    state_table = {}


# save state table on close
def sighandler(signum, frame):
    global state_table
    print('Killed by signal', signum, 'saving state', last_seq)
    with open(STATE_FILE, 'wb') as f:
        pickle.dump(state_table, f)
    sys.exit(0)


signal.signal(signal.SIGTERM, sighandler)
signal.signal(signal.SIGINT, sighandler)


class DatabaseFeedReader(BaseFeedReader):
    """
    Class for processing Known List changes.
    """

    def on_close(self):
        global state_table
        with open(STATE_FILE, 'wb') as f:
            pickle.dump(state_table, f)

    def on_message(self, message):
        global DEBUG, DB_NAME, state_table, kl

        # save the current seq in state table
        if 'last_seq' in message:
            state_table[DB_NAME]['last_seq'] = message['last_seq']
            return
        if 'seq' in message:
            state_table[DB_NAME]['last_seq'] = message['seq']

        if DEBUG:
            print('Received new msg=', message)

        # discard irrelevant messages
        if 'id' not in message:
            return

        # TODO: these events *might* be relevant
        if 'deleted' in message:
            return

        # retrieve the new KL entry
        doc_id = message['id']
        doc = self.db.get(doc_id)

        if DEBUG:
            print(doc)

        # check if the new entry is a complete KL record
        try:
            review_action = doc['review_action']
            review_type = doc['review_type']
            review_source = doc['review_source']
            owner_id = doc['owner_id']
        except KeyError as e:
            print('EXCEPTION new KL entry found, but seems to be incomplete', e, doc)
            return

        # update local classifier instance with the record newly received
        # from database
        kl.add(doc['_id'], owner_id, review_type, review_source, review_action)

        # find previously unclassified entries matching these criteria
        # view returns ["732349358731880803", "img-src", "https://assets.example.com"]
        # startkey is [owner_id, review_type] because it may be a wildcard
        # so it must be matched per report
        if DEBUG:
            print('\tReclassifying reports in database {}'.format(get_reports_db(owner_id)))
        try:
            reports_db = server.database(get_reports_db(owner_id))
        except pycouchdb.exceptions.NotFound:
            # this may happen if a rule was added for owner_id that has no reports, just ignore
            print('\t\tNo reports for {}, skipping'.format(owner_id))
            return
        for result in reports_db.query('reports/1300_unknown', include_docs=True,
                                       startkey=[owner_id, review_type],
                                       endkey=[owner_id, review_type, {}]):

            if DEBUG:
                print('\t\tProcessing report', result)

            if 'doc' not in result:
                continue

            report = result['doc']

            if 'csp-report' not in report:
                continue

            # check the new classification, with the KL change applied
            decision = kl.decision(owner_id, report['csp-report'])

            if DEBUG:
                # we use report.get() because the original report might have had no review before
                print('\t\tchange {} ==> {}'.format(report.get('review'), decision['action']))
                print('\t\tdecision=', decision)
                print('\t\treport=', report)

            # apply the classifier decision to the currently processed report
            review = {'decision': decision['action'], 'method': __file__, 'rule': decision['rule']}
            report['review'] = review

            # save classified report
            reports_db.save(report, batch=True)


if __name__ == '__main__':

    # retro only tracks changes the 'csp' database as it's where Known List is stored

    db = server.database(DB_NAME)

    if DEBUG:
        print('Starting the {} loop in database "{}"'.format(__file__, DB_NAME))

    while True:

        # check if states table entry is present for this db
        if DB_NAME not in state_table:
            state_table[DB_NAME] = {}
        if 'last_seq' not in state_table[DB_NAME]:
            state_table[DB_NAME]['last_seq'] = 0

        # restore the last_seq from state table
        last_seq = state_table[DB_NAME]['last_seq']

        # process updates in each database
        # the database object is passed automatically
        # by changes_feed() to the callback
        try:
            db.changes_feed(DatabaseFeedReader(), filter='csp/known_list', since=last_seq)
        # ValueError means the poll timed out and/or server returned empty line, just skip over it
        except ValueError:
            pass