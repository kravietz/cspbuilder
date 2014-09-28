#!/usr/bin/env python
# -*- coding: utf-8 -*-

import configparser
import hashlib
import os
from datetime import datetime, timezone
from flask import Flask, request, abort, make_response, redirect
from couchdb import Server
from fnmatch import fnmatch
from http.client import BadStatusLine
import re
import hmac

__author__ = 'pawelkrawczyk'

config = configparser.ConfigParser()
config.read(('collector.ini', os.path.join('collector', 'collector.ini'),
             os.path.join('..', 'collector', 'collector.ini')))

COUCHDB_SERVER = config.get('collector', 'couchdb_server')
ALLOWED_CONTENT_TYPES = [x.strip() for x in config.get('collector', 'mime_types').split(',')]
CSRF_KEY = b'fxwL8Ole62zSUXOk8LYKQlMweLs'

COUCHDB_SERVER = config.get('collector', 'couchdb_server')

app = Flask(__name__)
app.debug = True
server = Server('http://localhost:5984/')
db = server['csp']


@app.route('/login', methods=['POST'])
def login():
    start_time = datetime.now(timezone.utc)
    client_ip = request.environ.get('REMOTE_ADDR')

    owner_id = request.form.get('owner_id')

    print('login {} {} owner_id={}'.format(start_time, client_ip, owner_id))

    if not owner_id:
        print('login missing owner_id')
        return '', 400, []

    token = hmac.new(CSRF_KEY, bytes(owner_id, 'ascii'), hashlib.sha512).hexdigest()
    resp = make_response(redirect('/static/#/analysis'))
    resp.set_cookie('XSRF-TOKEN', token)
    resp.set_cookie('owner_id', str(owner_id))
    print('login setting token cookie {}'.format(token))
    return resp


def verify_csrf_token():
    request_token = request.headers.get('X-XSRF-TOKEN')
    owner_id = request.cookies.get('owner_id')
    print('verify_csrf_token owner_id={} request_token={}'.format(owner_id, request_token))

    if not (owner_id or request_token):
        print('verify_csrf_token missing owner_id or request token')
        return False

    expected_token = hmac.new(CSRF_KEY, bytes(owner_id, 'ascii'), hashlib.sha512).hexdigest()

    if hmac.compare_digest(request_token, expected_token):
        return True

    print('verify_csrf_token token mismatch expected_token={}'.format(expected_token))
    return False


def base_uri_match(a, b):
    """
    Compare origin of two URLs to check if they both come from the same origin.
    :param a: first URL
    :param b: second URL
    :return: True or False
    """
    r = re.match(r'^(https?://[^?#/]+)', a)
    if not r:
        return False
    a = r.group(1)

    r = re.match(r'^(https?://[^?#/]+)', b)
    if not r:
        return False
    b = r.group(1)

    return a == b


# TODO: set & verify CSRF headers
# TODO: authentication
@app.route('/api/<owner_id>/review', methods=['POST'])
def update_known_list(owner_id):
    start_time = datetime.now(timezone.utc)
    client_ip = request.environ.get('REMOTE_ADDR')

    if not verify_csrf_token():
        return '', 400, []

    data = request.json

    try:
        review_directive = data['review_type']
        review_source = data['review_source']
        review_action = data['review_action']
    except KeyError:
        print('update_known_list {} {} invalid input: {}'.format(start_time, client_ip, data))
        abort(400)

    # update known list entry
    # first check if there's such entry already
    try:
        results = db.view('csp/known_list', include_docs=True, startkey=[owner_id], endkey=[owner_id, {}])
    except (AttributeError, BadStatusLine) as e:
        print('read_csp_report exception {}'.format(e))
        return '', 204, []

    match = False

    for row in results:
        # "key":["9018643792216450862","font-src","https://fonts.gstatic.com","accept"]
        # filter by directive
        if row.key[1] == review_directive:
            # filter by source
            # so we might be adding "font-src","https://fonts.gstatic.com"
            # while "font-src","https://fonts.gstatic.com/some/other/" is already there
            if fnmatch(row.key[2], review_source + '*'):
                # new entry is shorter and more general - use it
                row.doc['review_source'] = review_source
                row.doc['review_method'] = 'user'
                db.save(row.doc)
                print('KL {} {} matched {} {} and is longer, update'.format(row.key[1], row.key[2], review_directive, review_source))
                print('update_known_list saved updated KL entry {}'.format(row.doc))
                match = True
                break
            elif row.key[2] == review_source:
                print('KL {} {} matched {} {}, skip and do not add new one'.format(row.key[1], row.key[2], review_directive, review_source))
                match = True
            else:
                print('KL {} {} does not match {} {}, skip as it will be added'.format(row.key[1], row.key[2], review_directive, review_source))

    if not match:
        # means the KL was not updated, create a new entry
        known_list_doc = {
            'owner_id': owner_id,
            'review_type': review_directive,
            'review_source': review_source,
            'review_action': review_action,
            # for audit
            'review_method': 'user',
            'client_ip': client_ip,
            'timestamp': start_time.isoformat(),
        }
        db.save(known_list_doc)
        print('update_known_list saved new KL entry {}'.format(known_list_doc))

    # review old reports matching the pattern (using bulk interface)
    action_to_status = {'accept': 'accepted', 'reject': 'rejected'}
    report_status = action_to_status[review_action]
    docs = []
    # the view does type filtering already
    for row in db.view('csp/1000_owner_type_src', include_docs=True,
                       startkey=[owner_id, review_directive], endkey=[owner_id, review_directive, {}]):
        # ["9018643792216450862", "img-src", "http://webcookies.info/static/no_photo_small.gif"]
        # this if covers two conditions: standard known list URI match, and 'self' URI match
        if (review_source == '\'self\'' and base_uri_match(row.key[2], row.doc['csp-report']['blocked-uri'])) \
                or fnmatch(row.key[2], review_source + '*'):
            doc = row.doc
            doc['reviewed'] = report_status
            # save the known list entry used to review this report
            doc['review_rule'] = [owner_id, review_directive, review_source, review_action]
            doc['review_method'] = 'user'
            docs.append(doc)

    if docs:
        db.update(docs)

    print('update_known_list updated status of {} existing reports'.format(len(docs)))

    stop_time = datetime.now(timezone.utc)
    print('update_known_list {} {} {} {}'.format(start_time, client_ip, request.url, stop_time - start_time))

    return '', 204, []


@app.route('/api/<owner_id>/all-reports', methods=['DELETE'])
def delete_all_reports(owner_id):
    start_time = datetime.now(timezone.utc)
    client_ip = request.environ.get('REMOTE_ADDR')

    if not verify_csrf_token():
        return '', 400, []

    docs = []
    for row in db.view('csp/all_by_owner', key=owner_id, include_docs=True):
        doc = row.doc
        doc['_deleted'] = True
        docs.append(doc)

    if docs:
        db.update(docs)

    stop_time = datetime.now(timezone.utc)
    print('delete_all_reports {} {} {} {} deleted {} reports'.format(start_time, client_ip, request.url,
                                                                     stop_time - start_time, len(docs)))

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
    document_uri = output['csp-report']['document-uri']

    print('read_csp_report type={} blocked_uri={}'.format(violated_directive, blocked_uri))

    # check list of known sources
    action = 'unknown'
    review_rule = 'default'

    # TODO: violated_directive could be used in CouchDB filter as it's static string
    try:
        results = db.view('csp/known_list', startkey=[owner_id], endkey=[owner_id, {}])
    except BadStatusLine as e:
        print('read_csp_report exception {}'.format(e))
        return '', 204, []

    print('read_csp_report {} known_list={}'.format(len(results), results))

    for row in results:
        # sample:
        # "key":["9018643792216450862","font-src","https://fonts.gstatic.com","accept"]
        known_directive = row.key[1]
        # append '*' so that 'http://api.google.com/blah/file.js' matches ''http://*.google.com'
        known_src = row.key[2]
        got_match = False
        # only process relevant directives
        # ownership is already limited at view level (startkey,endkey)
        if violated_directive == known_directive:
            print('read_csp_report matched directive violated_directive={} on blocked_uri={}'.format(violated_directive, blocked_uri))
            # if blocked resource's URI is the same as origin document's URI then
            # check if it's not allowed by 'self' entry
            if known_src == '\'self\'' and base_uri_match(blocked_uri, document_uri):
                print('read_csp_report match \'self\' on blocked_uri={} and document_uri={}'.format(blocked_uri, document_uri))
                got_match = True

            if fnmatch(blocked_uri, known_src + '*'):
                print('read_csp_report match on KL blocked_uri={} and known_src={}'.format(blocked_uri, known_src))
                got_match = True

            if got_match:
                # save the known list entry used to autoreview this report
                review_rule = row.key
                # actually copy the action from KL
                action = row.key[3]
                # stop processing other entries
                break

    output['review_rule'] = review_rule
    output['review_method'] = 'auto'
    action_to_status = {'accept': 'accepted', 'reject': 'rejected', 'unknown': 'not classified'}
    output['reviewed'] = action_to_status[action]

    # save current report to CouchDB
    db.save(output)

    stop_time = datetime.now(timezone.utc)

    print('read_csp_report {} {} {} {} action={} owner={} violated-directive={} blocked-uri={}'.format(start_time,
                                                                                                       client_ip,
                                                                                                       request.url,
                                                                                                       stop_time - start_time,
                                                                                                       action,
                                                                                                       owner_id,
                                                                                                       violated_directive,
                                                                                                       blocked_uri))

    return '', 204, []


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=8080)
