#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import re
import datetime
import time

from apihelpers.auth import login_response, verify_csrf_token
from apihelpers.utils import DocIdGen, ClientResolver, on_json_loading_failed, get_reports_db
from settings import ALLOWED_CONTENT_TYPES

__author__ = 'Paweł Krawczyk'

try:
    import ujson as json
except ImportError:
    import json

import os
from flask import Flask, request
import pycouchdb
from pycouchdb.exceptions import Conflict, NotFound

__author__ = 'Paweł Krawczyk'

DEBUG = False
if 'debug' in sys.argv:
    DEBUG = True

app = Flask(__name__)

# initialise database structures if necessary
server = pycouchdb.Server()

# the 'csp' database is the default database for configuration data etc
CSP_DB = 'csp'

state_table = {}

# sanity checks

# do we have database? if not, create
try:
    default_db = server.database(CSP_DB)
except NotFound:
    if DEBUG:
        print('Creating database "{}"'.format(CSP_DB))
    default_db = server.create(CSP_DB)

try:
    default_db.get('_design/csp')
except NotFound:
    if DEBUG:
        print('Uploading design document')
    default_db.upload_design(os.path.join('designs', 'csp'))

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


@app.route('/api/<owner_id>/init', methods=['POST'])
def init_owner_database(owner_id):
    try:
        server.create(get_reports_db(owner_id))
    except Conflict:
        # this means database already exists
        pass
    except Exception as e:
        print('Cannot create database for user {}: {}'.format(owner_id, e))
        return 'Cannot create database', 500, []

    try:
        server.database(get_reports_db(owner_id)).upload_design(os.path.join('designs', 'reports'))
    except Conflict:
        # this means design document is already there
        pass
    except Exception as e:
        print('Cannot upload design document user {}: {}'.format(owner_id, e))
        return 'Cannot init database', 500, []

    return '', 204, []


@app.route('/api/<owner_id>/all', methods=['DELETE'])
def reset_owner_database(owner_id):
    """
    Attached to the "delete all reports" button. Deletes the whole
    database and then reinitialises it.
    :param owner_id:
    """

    if not verify_csrf_token(request):
        return '', 400, []

    try:
        server.delete(get_reports_db(owner_id))
    except NotFound:
        return 'No reports', 404, []

    init_owner_database(owner_id)

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

    # replace Flask original JSON error handler with our own (apihelpers/utils.py)
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
        try:
            init_owner_database(owner_id)
        except Exception as e:
            print('Cannot initialise database for id {}: {}'.format(owner_id, e))
            return 'Cannot initialise database', 500, []

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

    # save GeoIP information which is passed as an array from Nginx
    geo = cr.get_geo(request)
    if type(geo) is list:
        meta['remote_geo'] = cr.get_geo(request)[0]
    else:
        meta['remote_geo'] = cr.get_geo(request)

    # save report UTC timestamp
    meta['timestamp'] = start_time.isoformat()

    # default lifetime is 1 day
    default_lifetime = 24*3600
    meta['expires'] = int(time.time()) + default_lifetime

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
        print('Saving', output)

    try:
        db.save(output, batch=True)
    except Conflict:
        if DEBUG:
            print('Conflict')
    except NotFound:
        if DEBUG:
            print('Database disappeared')

    return '', 204, []


if __name__ == '__main__':
    print('API starting, debugging=', DEBUG)
    app.run(host='0.0.0.0', debug=True, port=8088)
