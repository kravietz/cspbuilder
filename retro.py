#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Subscribes to CouchDB feed returning any new Known List entries and retroactively
reclassify reports that may be impacted by the changes.
"""
import sys
import signal

import pycouchdb
from pycouchdb.exceptions import NotFound
from pycouchdb.feedreader import BaseFeedReader

from apihelpers.known import KnownList
from apihelpers.state import State
from apihelpers.utils import get_reports_db


__author__ = 'Paweł Krawczyk'

server = pycouchdb.Server()

DEBUG = False
if 'debug' in sys.argv:
    DEBUG = True

# this is where Known List is stored
DB_NAME = 'csp'

kl = KnownList(server.database(DB_NAME), auto_update=False)
if DEBUG:
    print(kl)

# read CouchDB change feed 'seq' number to avoid reading through
# already processed changes in case of re-run
try:
    __file__
except NameError:
    __file__ = 'classify.py'
state = State(__file__)


# save state table on close
def sighandler(signum, frame):
    global state
    print('Killed by signal', signum, 'saving state', state.state)
    state.save()
    sys.exit(0)


signal.signal(signal.SIGTERM, sighandler)
signal.signal(signal.SIGINT, sighandler)


class DatabaseFeedReader(BaseFeedReader):
    """
    Class for processing Known List changes.
    """

    def on_close(self):
        global state
        state.save()

    def on_message(self, message):
        global DEBUG, state, kl, DB_NAME

        # save the current seq in state table
        if 'last_seq' in message:
            state.state[DB_NAME]['last_seq'] = message['last_seq']
            return
        if 'seq' in message:
            state.state[DB_NAME]['last_seq'] = message['seq']

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
        try:
            doc = self.db.get(doc_id)
        except NotFound:
            # report was deleted in the meantime
            return

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
            # sanity check to trigger NotFound before we try to fetch results
            reports_db.get('_design/reports')
        except NotFound:
            # this may happen if a rule was added for owner_id that has no reports, just ignore
            print('\t\tNo reports for {}, skipping'.format(owner_id))
            return
        for result in reports_db.query('reports/1300_unknown', include_docs=True,
                                       startkey=[owner_id, review_type],
                                       endkey=[owner_id, review_type, {}], limit=1000):

            if DEBUG:
                print('\t\tProcessing report', result)

            if 'doc' not in result:
                continue

            reclassified_report = result['doc']

            if 'csp-report' not in reclassified_report:
                continue

            # check the new classification, with the KL change applied
            decision = kl.decision(owner_id, reclassified_report['csp-report'])

            if DEBUG:
                # we use report.get() because the original report might have had no review before
                print('\t\tchange {} ==> {}'.format(reclassified_report.get('review'), decision['action']))
                print('\t\tdecision=', decision)
                print('\t\treport=', reclassified_report)

            # apply the classifier decision to the currently processed report
            review = {'decision': decision['action'], 'method': __file__, 'rule': decision['rule']}
            reclassified_report['review'] = review

            # save classified report
            try:
                reports_db.save(reclassified_report, batch=True)
            except Exception as e:
                print('Cannot save report', e, reclassified_report)


if __name__ == '__main__':

    # retro only tracks changes the 'csp' database as it's where Known List is stored

    db = server.database(DB_NAME)

    if DEBUG:
        print('Starting the {} loop in database "{}"'.format(__file__, DB_NAME))

    while True:

        # check if states table entry is present for this db
        if DB_NAME not in state.state:
            state.state[DB_NAME] = {}
        if 'last_seq' not in state.state[DB_NAME]:
            state.state[DB_NAME]['last_seq'] = 0

        # restore the last_seq from state table
        last_seq = state.state[DB_NAME]['last_seq']

        # process updates in each database
        # the database object is passed automatically
        # by changes_feed() to the callback
        try:
            # the source keyword is ignored by CouchDB but helps in debugging by identifying
            # which script generated this call
            db.changes_feed(DatabaseFeedReader(), filter='csp/known_list', since=last_seq, source=__file__)
        # ValueError means the poll timed out and/or server returned empty line, just skip over it
        except ValueError:
            pass
