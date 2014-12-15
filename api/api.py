#!/usr/bin/env python
# -*- coding: utf-8 -*-
import configparser
import hashlib
import json
import os
from datetime import datetime, timezone, timedelta
from fnmatch import fnmatch
import re
import hmac
import threading

from flask import Flask, request, abort, make_response, redirect
import pycouchdb
from netaddr import IPNetwork, IPAddress


__author__ = 'pawelkrawczyk'

config = configparser.ConfigParser()
config.read(('collector.ini', os.path.join('..', 'collector.ini')))

COUCHDB_SERVER = config.get('collector', 'couchdb_server')
ALLOWED_CONTENT_TYPES = [x.strip() for x in config.get('collector', 'mime_types').split(',')]
CSRF_KEY = config.get('api', 'api_key')
STORE_REJECTED = config.get('collector', 'store_accepted')
STORE_ACCEPTED = config.get('collector', 'store_rejected')
DEBUG = config.get('collector', 'debug') == 'True'
CLOUDFLARE_IPS = list(map(IPNetwork, config.get('api', 'cloudflare_ips').split()))
ACTION_MAP = {'accept': 'accepted', 'reject': 'rejected', 'unknown': 'not classified'}
COUCHDB_SERVER = config.get('collector', 'couchdb_server')

app = Flask(__name__)

if __name__ == '__main__':
    DB = 'csp_test'
else:
    DB = 'csp'

server = pycouchdb.Server()
try:
    db = server.database(DB)
except pycouchdb.exceptions.NotFound:
    db = server.create(DB)

try:
    db.get('_design/csp')
except pycouchdb.exceptions.NotFound:
    with open('etc/design.json') as file:
        doc = json.load(file)
        db.save(doc)

epoch = datetime.utcfromtimestamp(0)

# per https://docs.newrelic.com/docs/agents/python-agent/installation-configuration/python-agent-integration#manual-integration
import newrelic.agent
newrelic.agent.initialize('newrelic.ini')


def gen_id(owner_id):
    """
    Produce a CouchDB document identifer based on owner_id and current time.
    :param owner_id:
    :return: doc id
    """
    recv_time = (datetime.now() - epoch).total_seconds()

    return owner_id + str(recv_time)


def get_client_ip():
    """
    Obtain client IP from either standard REMOTE_ADDR variable or CloudFlare header.
    :return: IP address
    """
    client_ip = request.environ.get('REMOTE_ADDR')
    if not client_ip:
        return None
    # parse into IP
    client_ip = IPAddress(client_ip)
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


def get_client_geo():
    """
    Get client geolocation country from Nginx or CloudFlare variable.
    :return: country code like PL
    """
    ret = request.headers.get('CF-IPCountry')
    if ret:
        return ret
    ret = request.environ.get('GEOIP_COUNTRY')
    if ret:
        return ret
    return None


def login_response(owner_id):
    token = hmac.new(bytes(CSRF_KEY, 'ascii'), bytes(owner_id, 'ascii'), hashlib.sha512).hexdigest()
    resp = make_response(redirect('/static/#/analysis'))
    resp.set_cookie('XSRF-TOKEN', token, secure=True)
    resp.set_cookie('owner_id', owner_id, secure=True)
    print('login_response setting token cookie {}'.format(token))
    return resp


@app.route('/api/cleanup/week', methods=['POST'])
def cleanup_api():
    """
    Delete alerts that are older than 7 days. This function is gateway to the actual
    cleanup function that is started in background thread.
    """
    t = threading.Thread(target=cleanup, daemon=True)
    t.start()
    print('cleanup_api started thread {} {} alive={}'.format(t.name, t.ident, t.is_alive()))
    return '', 204, []


def cleanup():
    """
    Delete alerts that are older than 7 days. This the actual cleanup thread implementation.
    """
    print('cleanup thread starting')
    lv = threading.local()
    lv.start_time = datetime.now(timezone.utc)

    lv.results = True
    lv.total = 0
    # updating is done in batches; views can return thousands
    # of documents, which ends up in timeouts and excessive memory usage
    while lv.results:
        lv.i = 0
        lv.docs = []

        for row in db.query('csp/1910_stale', include_docs=True, limit=1000, skip=lv.total):
            # if alert is not marked as archived, add it to delete list
            if 'archived' not in row['doc'] or ('archived' in row['doc'] and row['doc']['archived'] != 'true'):
                # just copy the elements that are required to delete the document
                lv.docs.append({'_id': row['doc']['_id'], '_rev': row['doc']['_rev']})
            # total is used as offset for skip
            lv.total += 1
            # i is used to see if we got any rows at all
            lv.i += 1

        # does the database still return results?
        # it's done this way because py-couchdb returns generator
        lv.results = lv.i > 0
        print('i=', lv.i, 'total=', lv.total, 'lv.docs=', len(lv.docs))
        if len(lv.docs):
            db.delete_bulk(lv.docs)

    lv.run_time = datetime.now(timezone.utc) - lv.start_time

    print('cleanup deleted {} old reports, time {}'.format(lv.total, lv.run_time))


@app.route('/policy/<owner_id>/', methods=['GET'])
def policy(owner_id):
    """
    Quick login path via URL.
    """
    start_time = datetime.now(timezone.utc)
    print('policy login {} {} {} owner_id={}'.format(start_time, get_client_ip(), get_client_geo(), owner_id))
    return login_response(owner_id)


@app.route('/login', methods=['POST'])
def login():
    """
    Standard login via form and POST request.
    """
    start_time = datetime.now(timezone.utc)

    owner_id = request.form.get('owner_id')

    print('login {} {} {} owner_id={}'.format(start_time, get_client_ip(), get_client_geo(), owner_id))

    if not owner_id:
        print('login missing owner_id')
        return '', 400, []

    return login_response(owner_id)

def verify_csrf_token():
    """
    Utility function to verify CSRF token on API calls. Uses secret configured in .ini file
    and the owner_id from request.
    :param request: global HTTP request object
    :return: True if token correct, False if incorrect
    """
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
    print('review_old_reports thread starting')
    lv = threading.local()
    lv.start_time = datetime.now(timezone.utc)

    # rewrite the policy entry back into alert language
    # otherwise these reports will be never reviewed in the database
    if review_directive in ["'unsafe-inline'", "'unsafe-eval'"]:
        review_directive = 'null'

    # review old reports matching the pattern (using bulk interface)
    report_status = ACTION_MAP[review_action]

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
                            limit=1000,
                            skip=lv.total):

            # ["9018643792216450862", "img-src", "http://webcookies.info/static/no_photo_small.gif"]
            # this if covers two conditions: standard known list URI match, and 'self' URI match
            lv.match = False
            # null URLs can be matched by either inline or eval entries, per limitation of CSP 1.0
            if row['key'][2] == 'null' and review_source in ["'unsafe-inline'", "'unsafe-eval'"]:
                lv.match = True
            # self type matches
            if review_source == "'self'":
                # blocked URL matching document domain
                if base_uri_match(row['key'][2], row['doc']['csp-report']['blocked-uri']):
                    lv.match = True
                # literal "self" entry in report
                if row['key'][2] == "self":
                    lv.match = True
            # and finally, actual blocked URL is on known list
            if fnmatch(row['key'][2], review_source + '*'):
                lv.match = True
                
            # review report if match was found
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
        lv.results = lv.i > 0
        print('i=', lv.i, 'total=', lv.total, 'lv.docs=', len(lv.docs))
        if len(lv.docs):
            # print('update_known_list updating', lv.total)
            db.save_bulk(lv.docs)

    lv.run_time = datetime.now(timezone.utc) - lv.start_time

    print('review_old_reports updated status of {} existing reports, time {}'.format(lv.total, lv.run_time))


@app.route('/api/<owner_id>/all-reports', methods=['DELETE'])
def delete_all_reports(owner_id):
    start_time = datetime.now(timezone.utc)
    client_ip = get_client_ip()

    if not verify_csrf_token():
        return '', 400, []

    # this take a long time so push into a separate thread
    t = threading.Thread(target=delete_all_reports_thread, args=(owner_id,), daemon=True)

    t.start()

    print('delete_all_reports {} {} {} started background task {}'.format(start_time, client_ip, owner_id, t.ident))

    return '', 204, []


def delete_all_reports_thread(owner_id):
    lv = threading.local()

    lv.start_time = datetime.now(timezone.utc)

    print('delete_all_reports_thread starting for {} at {}'.format(owner_id, lv.start_time))

    lv.docs = []
    lv.i = 0

    # cycle through all reports for this user
    for row in db.query('csp/1200_all', key=owner_id, include_docs=True):
        # copy the document's crucial parts (id, rev), adding the _deleted flag
        lv.doc = {'_id': row['doc']['_id'], '_rev': row['doc']['_rev'], '_deleted': True}
        lv.docs.append(lv.doc)
        lv.i += 1

    print('delete_all_reports_thread {} found {} records to delete'.format(owner_id, lv.i))

    # actually delete these reports
    if lv.docs:
        db.save_bulk(lv.docs)

    lv.stop_time = datetime.now(timezone.utc)

    print('delete_all_reports_thread {} completed at {}'.format(owner_id, lv.stop_time))


def str_in_policy(p, t, s):
    """
    Find string s in statement of type t in CSP policy p.
    :param p: full policy string
    :param t: policy type to search in, such as script-src, style-src etc
    :param s: string to find
    :return: True if found, False otherwise
    """
    for st in map(s.strip, p.split(';')):
        if st.startswith(t):
            if st.find(s):
                return True
    return False


class Quota(object):
    quotas = {}
    limit = 1e6
    last_update = None

    def _load(self):
        for row in db.query('csp/1900_unique_sites', group=True, group_level=1, reduce=True):
            owner_id = row['key'][0]
            count = row['value']
            if count > self.limit:
                self.quotas[owner_id]
            if owner_id in self.quotas and count < self.limit:
                del self.quotas[owner_id]
        self.last_update = datetime.now(timezone.utc)

    def __init__(self):
        self._load()

    def check(self, owner_id):
        if datetime.now(timezone.utc) - self.last_update > timedelta(minutes=5):
            self._load()
        return owner_id in self.quotas


quota = Quota()


@app.route('/report/<owner_id>/', methods=['POST'])
def read_csp_report(owner_id):
    """
    Critical API call that actually reads CSP violation reports.
    :param owner_id: 19 digit identifier of the owner of the page
    """
    start_time = datetime.now(timezone.utc)

    if quota.check(owner_id):
        return 'Quota exceeded, please delete some reports', 400

    # sanity checks
    mimetype = request.headers.get('Content-Type')
    if mimetype not in ALLOWED_CONTENT_TYPES:
        return 'Invalid content type', 400

    output = request.get_json(force=True)

    if 'csp-report' not in output:
        return 'CSP report missing', 400

    output['owner_id'] = owner_id

    # add document identifier; this is important for performance
    # otherwise py-couchdb will add a random one
    output['_id'] = gen_id(owner_id)

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

    # ## SANITIZATIONS AND REWRITES ON THE ORIGINAL REPORT

    # if blocked-uri is empty, replace it with "null" string
    # otherwise JS views in CouchDB will not be able to find it
    if output['csp-report']['blocked-uri'] == "":
        output['csp-report']['blocked-uri'] = "null"

    # trim data: URIs removing potentially large BASE64 blobs
    # this is purely for performance and space-saving reasons
    # https://tools.ietf.org/html/rfc2397
    if output['csp-report']['blocked-uri'].startswith('data:'):
        output['csp-report']['blocked-uri'] = output['csp-report']['blocked-uri'].split(',')[0]

    violated_directive = output['csp-report']['violated-directive'].split()[0]
    blocked_uri = output['csp-report']['blocked-uri']
    document_uri = output['csp-report']['document-uri']
    original_policy = output['csp-report'].get('original-policy')

    # check list of known sources
    action = 'unknown'
    review_rule = 'default'

    # TODO: violated_directive could be used in CouchDB filter as it's static string
    results = db.query('csp/1000_known_list', key=owner_id)

    for row in results:
        # sample:
        # "key":["9018643792216450862","font-src","https://fonts.gstatic.com","accept"]
        known_directive = row['value'][0]
        known_src = row['value'][1]
        got_match = False

        # only process relevant directives
        # ownership is already limited at view level (key)

        if violated_directive == known_directive:

            # source URI just matches known pattern
            if fnmatch(blocked_uri, known_src + '*'):
                got_match = True

            # in case of "null" blocked URI we don't really know
            # if it's eval or inline, so any of these approves this
            if blocked_uri == "null":
                # attempt to use simple heuristics: if eval was allowed, then
                # it must have been inline - and vice versa
                if original_policy and str_in_policy(original_policy, violated_directive, "'unsafe-inline'"):
                    if known_src == "'unsafe-eval'":
                        got_match = True
                if original_policy and str_in_policy(original_policy, violated_directive, "'unsafe-eval'"):
                    if known_src == "'unsafe-inline'":
                        got_match = True

            # check for 'self' entries
            # variant 1 - report contains literal 'self' source
            if known_src == '\'self\'' and blocked_uri == 'self':
                got_match = True
            # variant 2 - blocked URI is the same as document URI
            if known_src == '\'self\'' and base_uri_match(blocked_uri, document_uri):
                got_match = True

            if DEBUG:
                print('read_csp_report: match={} blocked uri={} type={}, KL={}'.format(got_match, blocked_uri,
                                                                                       violated_directive, row))

            if got_match:
                # save the known list entry used to autoreview this report
                review_rule = row['value']
                # execute the action from known list
                action = row['value'][2]
                break

    # known reports are only stored if configured to do so
    store = False
    if action == 'reject' and STORE_REJECTED:
        store = True
    if action == 'accept' and STORE_ACCEPTED:
        store = True
    # unknown reports are stored always
    if action == 'unknown':
        store = True

    # add metadata and store result
    if store:
        output['review_rule'] = review_rule
        output['review_method'] = 'auto'
        output['reviewed'] = ACTION_MAP[action]

        # save current report to CouchDB
        db.save(output, batch=True)
        stop_time = datetime.now(timezone.utc)
        print('read_csp_report {} {} {} {} {} action={} owner={} violated-directive={} blocked-uri={}'.format(start_time,
                                                                                                           get_client_ip(), get_client_geo(),
                                                                                                           request.url,
                                                                                                           stop_time - start_time,
                                                                                                           action,
                                                                                                           owner_id,
                                                                                                           violated_directive,
                                                                                                           blocked_uri))

    return 'Report accepted', 204, []

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=8088)
