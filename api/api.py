#!/usr/bin/env python
# -*- coding: utf-8 -*-
import configparser
import hashlib
import os
from datetime import datetime, timezone
from fnmatch import fnmatch
import re
import hmac
import threading

from flask import Flask, request, abort, make_response, redirect
import pycouchdb
from netaddr import IPNetwork, IPAddress


__author__ = 'pawelkrawczyk'

config = configparser.ConfigParser()
config.read(('collector.ini', os.path.join('collector', 'collector.ini'),
             os.path.join('..', 'collector', 'collector.ini')))

COUCHDB_SERVER = config.get('collector', 'couchdb_server')
ALLOWED_CONTENT_TYPES = [x.strip() for x in config.get('collector', 'mime_types').split(',')]
CSRF_KEY = config.get('api', 'api_key')
CLOUDFLARE_IPS = list(map(IPNetwork, config.get('api', 'cloudflare_ips').split()))

COUCHDB_SERVER = config.get('collector', 'couchdb_server')

app = Flask(__name__)
app.debug = True
server = pycouchdb.Server(COUCHDB_SERVER)
db = server.database('csp')


def get_client_ip():
    client_ip = IPAddress(request.environ.get('REMOTE_ADDR'))
    for net in CLOUDFLARE_IPS:
        if client_ip in net:
            # this is CloudFlare network, try to extract real IP
            cf_ip = request.headers.get('CF-Connecting-IP')
            if cf_ip:
                return cf_ip
            else:
                print('get_client_ip request came from CloudFlare IP {} but did not contain CF-Connecting-IP'.format(client_ip))
    # return original IP otherwise
    return str(client_ip)


def login_response(owner_id):
    token = hmac.new(bytes(CSRF_KEY, 'ascii'), bytes(owner_id, 'ascii'), hashlib.sha512).hexdigest()
    resp = make_response(redirect('/static/#/analysis'))
    resp.set_cookie('XSRF-TOKEN', token)
    resp.set_cookie('owner_id', owner_id)
    print('login_response setting token cookie {}'.format(token))
    return resp

@app.route('/policy/<owner_id>/', methods=['GET'])
def policy(owner_id):
    start_time = datetime.now(timezone.utc)
    client_ip = get_client_ip()
    print('policy login {} {} owner_id={}'.format(start_time, client_ip, owner_id))
    return login_response(owner_id)


@app.route('/login', methods=['POST'])
def login():
    start_time = datetime.now(timezone.utc)
    client_ip = get_client_ip()

    owner_id = request.form.get('owner_id')

    print('login {} {} owner_id={}'.format(start_time, client_ip, owner_id))

    if not owner_id:
        print('login missing owner_id')
        return '', 400, []

    return login_response(owner_id)

def verify_csrf_token():
    request_token = request.headers.get('X-XSRF-TOKEN')
    owner_id = request.cookies.get('owner_id')
    print('verify_csrf_token owner_id={} request_token={}'.format(owner_id, request_token))

    if not (owner_id or request_token):
        print('verify_csrf_token missing owner_id or request token')
        return False

    expected_token = hmac.new(bytes(CSRF_KEY, 'ascii'), bytes(owner_id, 'ascii'), hashlib.sha512).hexdigest()

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


@app.route('/api/<owner_id>/review', methods=['POST'])
def update_known_list(owner_id):
    start_time = datetime.now(timezone.utc)
    client_ip = get_client_ip()

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
    match = False
    for row in db.query('csp/1000_known_list', include_docs=True, startkey=[owner_id], endkey=[owner_id, {}]):
        # "key":["9018643792216450862","font-src","https://fonts.gstatic.com","accept"]
        # filter by directive
        if row['key'][1] == review_directive:
            # filter by source
            # so we might be adding "font-src","https://fonts.gstatic.com"
            # while "font-src","https://fonts.gstatic.com/some/other/" is already there
            if fnmatch(row['key'][2], review_source + '*'):
                # new entry is shorter and more general - use it
                row['doc']['review_source'] = review_source
                row['doc']['review_method'] = 'user'
                db.save(row['doc'])
                print('KL {} {} matched {} {} and is longer, update'.format(row['key'][1], row['key'][2], review_directive, review_source))
                print('update_known_list saved updated KL entry {}'.format(row['doc']))
                match = True
                break
            elif row['key'][2] == review_source:
                print('KL {} {} matched {} {}, skip and do not add new one'.format(row['key'][1], row['key'][2], review_directive, review_source))
                match = True
            else:
                print('KL {} {} does not match {} {}, skip as it will be added'.format(row['key'][1], row['key'][2], review_directive, review_source))

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

    # this take a long time so push into a separate thread
    t = threading.Thread(target=review_old_reports,
                         args=(owner_id, review_directive, review_source, review_action),
                         daemon=True)
    t.start()
    print('update_known_list started thread {} {} alive={}'.format(t.name, t.ident, t.is_alive()))

    stop_time = datetime.now(timezone.utc)
    print('update_known_list {} {} {} {}'.format(start_time, client_ip, request.url, stop_time - start_time))

    return '', 204, []


def review_old_reports(owner_id, review_directive, review_source, review_action):
    print('starting review_old_reports thread')
    lv = threading.local()
    lv.start_time = datetime.now(timezone.utc)

    # rewrite the policy entry back into alert language
    # otherwise these reports will be never reviewed in the database
    if review_directive in ["'unsafe-inline'", "'unsafe-eval'"]:
        review_directive = 'null'

    # review old reports matching the pattern (using bulk interface)
    action_to_status = {'accept': 'accepted', 'reject': 'rejected'}
    report_status = action_to_status[review_action]

    lv.results = True
    lv.total = 0
    # updating is done in batches; views can return thousands
    # of documents, which ends up in timeouts and excessive memory usage
    while lv.results:
        lv.i = 0
        lv.docs = []

        for row in db.query('csp/1300_unknown', include_docs=True,
                            startkey=[owner_id, review_directive],
                            endkey=[owner_id, review_directive, {}],
                            limit=100,
                            skip=lv.total):
            # ["9018643792216450862", "img-src", "http://webcookies.info/static/no_photo_small.gif"]
            # this if covers two conditions: standard known list URI match, and 'self' URI match
            lv.match = False
            if review_source == "'self'" and base_uri_match(row['key'][2], row['doc']['csp-report']['blocked-uri']):
                lv.match = True
            if fnmatch(row['key'][2], review_source + '*'):
                lv.match = True
            if lv.match:
                lv.doc = row['doc']
                lv.doc['reviewed'] = report_status
                # save the known list entry used to review this report
                lv.doc['review_rule'] = [owner_id, review_directive, review_source, review_action]
                lv.doc['review_method'] = 'user'
                lv.docs.append(lv.doc)
            # total is used as offset for skip
            lv.total += 1
            # i is used to see if we got any rows at all
            lv.i += 1

        # does the database still return results?
        # it's done this way because py-couchdb returns generator
        results = lv.i > 0
        print('i=', lv.i, 'total=', lv.total)
        if results:
            print('update_known_list updating', lv.total)
            db.save_bulk(lv.docs)

    lv.run_time = datetime.now(timezone.utc) - lv.start_time

    print('update_known_list updated status of {} existing reports, time {}'.format(lv.total, lv.run_time))


@app.route('/api/<owner_id>/all-reports', methods=['DELETE'])
def delete_all_reports(owner_id):
    start_time = datetime.now(timezone.utc)
    client_ip = get_client_ip()

    if not verify_csrf_token():
        return '', 400, []

    docs = []
    for row in db.query('csp/1200_all', key=owner_id, include_docs=True):
        doc = row['doc']
        doc['_deleted'] = True
        docs.append(doc)

    if docs:
        db.save_bulk(docs)

    stop_time = datetime.now(timezone.utc)
    print('delete_all_reports {} {} {} {} deleted {} reports'.format(start_time, client_ip, request.url,
                                                                     stop_time - start_time, len(docs)))

    return '', 204, []


@app.route('/report/<owner_id>/', methods=['POST'])
def read_csp_report(owner_id):
    start_time = datetime.now(timezone.utc)

    # sanity checks
    mimetype = request.headers.get('Content-Type')
    if mimetype not in ALLOWED_CONTENT_TYPES:
        return 'Invalid content type', 400, []

    output = request.get_json(force=True)

    if 'csp-report' not in output:
        return 'CSP report missing', 400, []

    output['owner_id'] = owner_id

    # fill-in metadata for current report from HTTP headers
    meta = {}

    # User-Agent header
    user_agent = request.environ.get('HTTP_USER_AGENT')
    meta['user_agent'] = user_agent

    client_ip = get_client_ip()
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

    # check list of known sources
    action = 'unknown'
    review_rule = 'default'

    # TODO: violated_directive could be used in CouchDB filter as it's static string
    results = db.query('csp/1000_known_list', startkey=[owner_id], endkey=[owner_id, {}])

    for row in results:
        # sample:
        # "key":["9018643792216450862","font-src","https://fonts.gstatic.com","accept"]
        known_directive = row['key'][1]
        # append '*' so that 'http://api.google.com/blah/file.js' matches ''http://*.google.com'
        known_src = row['key'][2]
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
                review_rule = row['key']
                # actually copy the action from KL
                action = row['key'][3]
                # stop processing other entries
                break

    # only store reports from unknown and accepted sources
    if action in ['unknown', 'reject']:
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
    app.run(host='0.0.0.0', debug=True, port=80)
