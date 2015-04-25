#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Subscribes to CouchDB feeds returning any new unclassified documents and classify them in real time.
Use KnownList object that will update itself automatically on periodic basis.
"""
import pickle
import sys
import signal
import os

import pycouchdb

from apihelpers.known import KnownList
from apihelpers.utils import REPORTS_DB_PREFIX
from settings import CLASSIFY_INTERVAL


__author__ = 'Paweł Krawczyk'

server = pycouchdb.Server()

DEBUG = False
if 'debug' in sys.argv:
    DEBUG = True

# this is where Known List is stored
DB_NAME = 'csp'

state_table = {}

kl = KnownList(server.database(DB_NAME), verbose=True)
if DEBUG:
    print(kl)

from pycouchdb.feedreader import BaseFeedReader

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


class ReportsFeedReader(BaseFeedReader):
    """
    Class for processing Known List changes.
    """

    def on_close(self):
        global last_seq
        with open(STATE_FILE, 'wb') as f:
            pickle.dump(state_table, f)

    def on_message(self, message):
        global DEBUG, state_table, kl

        # save the current seq in state table
        if 'last_seq' in message:
            state_table[DB_NAME]['last_seq'] = message['last_seq']
            return
        # these are coming along with real messages
        if 'seq' in message:
            state_table[DB_NAME]['last_seq'] = message['seq']

        if DEBUG:
            print('Received new msg=', message)

        # # discard irrelevant messages
        if 'id' not in message:
            return
        if 'deleted' in message:
            return

        # fetch the actual report referenced in the update message
        doc_id = message['id']
        try:
            # the self.db object already stores handle for the relevant reports database
            doc = self.db.get(doc_id)
        # the document might have been deleted in the meantime, just ignore it
        except pycouchdb.exceptions.NotFound:
            return

        # sanity check, just in case (no such docs should come from the filter)
        if 'csp-report' not in doc:
            return

        owner_id = doc['owner_id']
        report = doc['csp-report']

        # obtain classifier decision based on the current Known List
        print('KL=', kl)
        decision = kl.decision(owner_id, report)

        # update the review field
        review = {'decision': decision['action'], 'method': __file__, 'rule': decision['rule']}
        doc['review'] = review

        if DEBUG:
            print('\tclassify={} decision={}'.format(decision['action'], decision))
            print('\tdoc={}'.format(doc))

        # finally save the classified document back to database
        try:
            self.db.save(doc, batch=True)
        except pycouchdb.exceptions.Conflict as ex:
            print('\t', ex, doc)

# start the main loop of the Classifier
if __name__ == '__main__':

    if DEBUG:
        print('Starting the loop...')

    while True:
        # cycle through all report databases on the servers and check recent changes
        for db in server:

            # from now on only process reports databases
            if not db.startswith(REPORTS_DB_PREFIX):
                continue

            # check if states table entry is present for this db
            if db not in state_table:
                state_table[db] = {}
            if 'last_seq' not in state_table[db]:
                state_table[db]['last_seq'] = 0

            last_seq = state_table[db]['last_seq']

            # process updates in each database
            # the database object is passed automatically
            # by changes_feed() to the callback
            try:
                server.database(db).changes_feed(ReportsFeedReader(), filter='reports/unclassified', since=last_seq,
                    timeout=CLASSIFY_INTERVAL)
            # this means the poll timed out and server returned empty line, just skip over it
            except ValueError:
                pass