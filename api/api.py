#!/usr/bin/env python
# -*- coding: utf-8 -*-
import configparser
import os
from datetime import datetime, timezone
from flask import Flask, request, abort
from couchdb import Server
import re

__author__ = 'pawelkrawczyk'

config = configparser.ConfigParser()
config.read(('collector.ini', os.path.join('collector', 'collector.ini'),
             os.path.join('..', 'collector', 'collector.ini')))

COUCHDB_SERVER = config.get('collector', 'couchdb_server')
ALLOWED_CONTENT_TYPES = [x.strip() for x in config.get('collector', 'mime_types').split(',')]

COUCHDB_SERVER = config.get('collector', 'couchdb_server')

app = Flask(__name__)
server = Server('http://localhost:5984/')
db = server['csp']

# TODO: set & verify CSRF headers
# TODO: authentication
@app.route('/api/<owner_id>/review', methods=['POST'])
def review_type_source(owner_id):
    start_time = datetime.now(timezone.utc)
    client_ip = request.environ.get('REMOTE_ADDR')

    data = request.json

    try:
        review_type   = data['review_type']
        review_source = data['review_source']
        review_action = data['review_action']
    except KeyError:
        print('review_type_source {} {} invalid input: {}'.format(start_time, client_ip, data))
        abort(400)

    # save known list entry for auto-reviewing of future reports
    results = db.view('csp/known_list',
                       include_docs=True, reduce=False,
                       startkey=[owner_id, review_type, review_source],
                       endkey=[owner_id, review_type, {}])

    if not len(results):
        # no entries for this type and source were found - add a new one
        doc = {
            'owner_id': owner_id,
            'review_type': review_type,
            'review_source': review_source,
            'review_action': review_action,
            # for audit
            'client_ip': client_ip,
            'timestamp': start_time,
        }
        db.save(doc)
    else:
        # entries were found, just leave one and update its action
        first = True
        for row in results:
            if first:
                doc = row.doc
                doc['review_action'] = review_action
                doc['client_ip'] = client_ip
                doc['timestamp'] = start_time
                db.save(doc)
                first = False
            else:
                db.delete(doc)

    # review old reports matching the pattern (using bulk interface)
    docs = []
    for row in db.view('csp/grouped_types_sources',
                       include_docs=True, reduce=False,
                       startkey=[owner_id, review_type, review_source],
                       endkey=[owner_id, review_type, {}]):
        doc = row.doc
        doc['reviewed'] = review_action
        docs.append(doc)

    db.update(docs)

    stop_time = datetime.now(timezone.utc)
    print('review_type_source {} {} {} {}'.format(start_time, client_ip, request.url, stop_time - start_time))

    return '', 204, []

@app.route('/api/<owner_id>/all-reports', methods=['DELETE'])
def delete_all_reports(owner_id):
    start_time = datetime.now(timezone.utc)
    client_ip = request.environ.get('REMOTE_ADDR')

    docs = []
    for row in db.view('csp/all_by_owner', key=owner_id, include_docs=True):
        doc = row.doc
        doc['_deleted'] = True
        docs.append(doc)

    db.update(docs)

    stop_time = datetime.now(timezone.utc)
    print('delete_all_reports {} {} {} {}'.format(start_time, client_ip, request.url, stop_time - start_time))

    return '', 204, []

@app.route('/report/<owner_id>', methods=['POST'])
def read_csp_report(owner_id):

    start_time = datetime.now(timezone.utc)

    mimetype = request.headers['Content-Type']

    if mimetype not in ALLOWED_CONTENT_TYPES:
        return 'Invalid content type', 400, []

    output = request.get_json(force=True)

    output['owner_id'] = owner_id

    # fill-in metadata for current report from HTTP headers
    meta = {}

    # User-Agent header
    user_agent = request.environ.get('HTTP_USER_AGENT')
    meta['user_agent'] = user_agent

    client_ip = request.environ.get('REMOTE_ADDR')
    # save client's IP address
    meta['remote_ip'] = client_ip

    # UTC timestamp
    meta['timestamp'] = start_time.isoformat()

    # copy metadata into the final report object
    output['meta'] = meta

    # if blocked-uri is empty, replace it with null value
    # otherwise JS views will not be able to find it
    if output['csp-report']['blocked-uri'] == "":
        output['csp-report']['blocked-uri'] = "null"

    violated_directive = output['csp-report']['violated-directive'].split()[0]
    blocked_uri = output['csp-report']['blocked-uri']

    # get basic URI template for match with known list
    r = re.match(r'^(https?://[^?#/]+)', blocked_uri)
    if r:
        uri_template = r.group(0)
    else:
        uri_template = blocked_uri

    # check list of known sources
    action = 'unknown'
    for row in db.view('csp/known_list',
                       startkey=[owner_id, violated_directive, uri_template, ""],
                       endkey=[owner_id, violated_directive, uri_template, {}]):
        action = row.key[3]
        # entry found, classify the new alert
        if action == 'accept':
            output['reviewed'] = 'accepted'
        else:
            output['reviewed'] = 'rejected'

    # save current report to CouchDB
    db.save(output)

    stop_time = datetime.now(timezone.utc)

    print('read_csp_report {} {} {} {} action={} owner={} violated-directive={} blocked-uri={}'.format(start_time, client_ip,
                                                                                       request.url,
                                                                                       stop_time - start_time, action,
                                                                                       owner_id,
                                                                                       violated_directive, blocked_uri))

    return '', 204, []


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=8080)
