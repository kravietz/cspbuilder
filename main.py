#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys

import re
from api.auth import login_response, verify_csrf_token
from api.delete import delete_all_reports_task
from api.utils import DocIdGen, ClientResolver, on_json_loading_failed, get_reports_db


__author__ = 'Paweł Krawczyk'

import configparser
import datetime

try:
    import ujson as json
except ImportError:
    import json

import os
import threading
from flask import Flask, request
import pycouchdb

config = configparser.ConfigParser()
config.read(('collector.ini', os.path.join('..', 'collector.ini')))

ALLOWED_CONTENT_TYPES = [x.strip() for x in config.get('collector', 'mime_types').split(',')]
DESIGN_DOCUMENT = json.load(open(os.path.join('etc', 'design.json')))

DEBUG = False
if 'debug' in sys.argv:
    DEBUG = True

app = Flask(__name__)

if __name__ != '__main__':
    # Flask is considered unsupported by NewRelic http://goo.gl/gP26Dj
    import newrelic.agent
    newrelic.agent.initialize('newrelic.ini')

# initialise database structures if necessary
server = pycouchdb.Server()

# the 'csp' database is the default database for configuration data etc
DEFAULT_DB = 'csp'

state_table = {}

# create if not there (first run)
try:
    default_db = server.database(DEFAULT_DB)
except pycouchdb.exceptions.NotFound:
    if DEBUG:
        print('Database was uninitialised, doing it now')
    default_db = server.create(DEFAULT_DB)
    # TODO: maintain different design documents for 'csp' and report databases
    default_db.save(DESIGN_DOCUMENT)

# initialise quota checker
# TODO: reimplement quota to support new database layout

# initialise client IP and geoIP resolver
cr = ClientResolver()


@app.route('/policy/<owner_id>/', methods=['GET'])
def quick_login(owner_id):
    """
    Quick login path via URL.
    """
    start_time = datetime.datetime.now(datetime.timezone.utc)

    print('quick login {} {} {} owner_id={}'.format(start_time, cr.get_ip(request), cr.get_geo(request), owner_id))

    return login_response(owner_id)


@app.route('/api/<owner_id>/<report_id>', methods=['DELETE'])
def delete_report(owner_id, report_id):
    """
    Delete a single report by its database id.
    :param owner_id:
    :param report_id:
    :return: HTTP response
    """

    if not verify_csrf_token(request):
        return '', 400, []

    try:
        db = server.database(get_reports_db(owner_id))
    except pycouchdb.exceptions.NotFound:
        return 'No reports', 404, []

    try:
        report = db.get(report_id)
    except pycouchdb.exceptions.NotFound:
        return 'No such report', 404, []

    if 'owner_id' in report and report['owner_id'] == owner_id:
        db.delete(report_id)
        print('Delete report', owner_id, report_id)
        return '', 204, []
    else:
        return 'Owner mismatch', 400, []


@app.route('/login', methods=['POST'])
def login():
    """
    Standard login via form and POST request.
    """
    start_time = datetime.datetime.now(datetime.timezone.utc)

    owner_id = request.form.get('owner_id')

    print('form login {} {} {} owner_id={}'.format(start_time, cr.get_ip(request), cr.get_geo(request), owner_id))

    if not owner_id:
        print('login missing owner_id')
        return 'Missing owner id', 400, []

    return login_response(owner_id)


@app.route('/api/<owner_id>/all-reports', methods=['DELETE'])
def delete_all_reports(owner_id):
    start_time = datetime.datetime.now(datetime.timezone.utc)
    client_ip = cr.get_ip(request)

    if not verify_csrf_token(request):
        return '', 400, []

    try:
        db = server.database(get_reports_db(owner_id))
    except pycouchdb.exceptions.NotFound:
        return 'No reports', 404, []

    # this take a long time so push into a separate thread
    t = threading.Thread(target=delete_all_reports_task, args=(owner_id, db,), daemon=True)

    t.start()

    print('delete_all_reports {} {} {} started background task {}'.format(start_time, client_ip, owner_id, t.ident))

    return '', 204, []


TAG_R = re.compile(r'^[a-zA-Z0-9-]+$')
OWNER_ID_R = re.compile(r'^[0-9]{,20}$')

@app.route('/report/<owner_id>/<tag>/', methods=['POST'])
@app.route('/report/<owner_id>/', methods=['POST'])
def read_csp_report(owner_id, tag=None):
    """
    Read CSP violation report, perform sanity checks and save it to the database
    as soon as possible. Reports are written as unclassified here, classification
    is performed by Classifier Service.

    :param owner_id:
    :return: 204 No Content
    """
    start_time = datetime.datetime.now(datetime.timezone.utc)

    # ### VALIDATION ###

    # silently discard the report if quota is exceeded for this id
    # TODO: reimplement with new db layout
    # if quota_checker.check(owner_id):
    #    return '', 204, []

    # sanity checks
    mime_type = request.headers.get('Content-Type')
    if mime_type not in ALLOWED_CONTENT_TYPES:
        err = 'Invalid content type'
        print(err, mime_type)
        return '{}\n'.format(err), 400

    # validate owner id
    if not OWNER_ID_R.match(owner_id):
        err = 'Invalid owner id'
        print(err, owner_id)
        return '{}\n'.format(err), 400

    # validate sanity of tags
    if tag and not TAG_R.match(tag):
        err = 'Invalid tag'
        print(err, tag)
        return '{}\n'.format(err), 400

    # replace Flask original JSON error handler with our own (api/utils.py)
    request.on_json_loading_failed = on_json_loading_failed

    # ### START BUILDING OUTPUT ###

    # try to decode JSON from input, will throw error in syntax invalid
    output = request.get_json(force=True)

    # if we got here, the JSON was syntactically correct
    # perform semantic sanity checks on the unserialized input
    if 'csp-report' not in output:
        err = 'CSP report missing'
        print(err, output)
        return '{}\n'.format(err), 400

    for item in ['blocked-uri', 'document-uri', 'violated-directive']:
        if item not in output['csp-report']:
            err = 'CSP report incomplete'
            print(err, item, output['csp-report'])
            return '{}\n'.format(err), 400

    output['owner_id'] = owner_id

    # check if database for this owner_id exists
    # create & initialize if not
    try:
        db = server.database(get_reports_db(owner_id))
    except pycouchdb.exceptions.NotFound:
        # noinspection PyBroadException
        try:
            db = server.create(get_reports_db(owner_id))
            db.save(DESIGN_DOCUMENT)
        except Exception as e:
            err = 'Could not initialise database'
            print(err, e)
            return '{}\n'.format(err), 500

    # add document identifier; this is important for performance
    # otherwise py-couchdb will add a random one
    if owner_id not in state_table:
        state_table[owner_id] = {}

    if 'doc_id' not in state_table[owner_id]:
        state_table[owner_id]['doc_id'] = DocIdGen(db)

    # assign document identifier
    doc_id_gen = state_table[owner_id]['doc_id']
    output['_id'] = doc_id_gen.new_id()

    # fill-in metadata for current report from HTTP headers
    meta = {}

    # save reporting User-Agent
    user_agent = request.environ.get('HTTP_USER_AGENT')
    meta['user_agent'] = user_agent

    # save reporting client's IP information
    meta['remote_ip'] = cr.get_ip(request)
    meta['remote_geo'] = cr.get_geo(request),

    # save report UTC timestamp
    meta['timestamp'] = start_time.isoformat()

    # if tag was sent in the report, add it
    if tag:
        meta['tag'] = str(tag)

    # copy metadata into the final report object
    output['meta'] = meta

    # sanitize and rewrite the actual CSP report

    # if blocked-uri is empty, replace it with "null" literal
    # otherwise JS views in CouchDB will not be able to find it
    if output['csp-report']['blocked-uri'] == "":
        output['csp-report']['blocked-uri'] = "null"

    # trim data for performance and space-saving reasons
    # data URIs can  potentially contain large BASE64 blobs
    # this preserves the MIME type name, e.g.
    # data:application/javascript data:image/png
    # https://tools.ietf.org/html/rfc2397
    if output['csp-report']['blocked-uri'].startswith('data:'):
        output['csp-report']['blocked-uri'] = output['csp-report']['blocked-uri'].split(',')[0]

    if DEBUG:
        print(output)

    db.save(output, batch=True)

    return '', 204, []


if __name__ == '__main__':
    print('API starting, debugging=', DEBUG)
    app.run(host='0.0.0.0', debug=True, port=8088)
