#!/usr/bin/env python
# -*- coding: utf-8 -*-
from api.auth import login_response, verify_csrf_token
from api.delete import delete_all_reports_task
from api.quota import Quota
from api.utils import DocIdGen, ClientResolver, on_json_loading_failed

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

app = Flask(__name__)

if __name__ == '__main__':
    # run on test database if started from command line
    DB = 'csp'
else:
    # run on production database if started by uwsgi
    DB = 'csp'
    # Flask is considered unsupported by NewRelic http://goo.gl/gP26Dj
    import newrelic.agent

    newrelic.agent.initialize('newrelic.ini')

# initialise database structures if necessary
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

# initialise document id generator
doc_id_generator = DocIdGen()

# initialise quota checker
quota_checker = Quota(db)

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


@app.route('/api/<owner_id>/all-reports', methods=['DELETE'])
def delete_all_reports(owner_id):
    start_time = datetime.datetime.now(datetime.timezone.utc)
    client_ip = cr.get_ip(request)

    if not verify_csrf_token(request):
        return '', 400, []

    # this take a long time so push into a separate thread
    t = threading.Thread(target=delete_all_reports_task, args=(owner_id, db,), daemon=True)

    t.start()

    print('delete_all_reports {} {} {} started background task {}'.format(start_time, client_ip, owner_id, t.ident))

    return '', 204, []


@app.route('/report/<owner_id>/', methods=['POST'])
def read_csp_report(owner_id):
    """
    Read CSP violation report, perform sanity checks and save it to the database
    as soon as possible. Reports are written as unclassified here, classification
    is performed by Classifier Service.
    """
    start_time = datetime.datetime.now(datetime.timezone.utc)

    # silently discard the report if quota is exceeded for this id
    if quota_checker.check(owner_id):
        return '', 204, []

    # sanity checks
    mime_type = request.headers.get('Content-Type')
    if mime_type not in ALLOWED_CONTENT_TYPES:
        return 'Invalid content type\n'.format(mime_type), 400

    # replace Flask original JSON error handler with our own (api/utils.py)
    request.on_json_loading_failed = on_json_loading_failed
    # try to decode JSON from input
    output = request.get_json(force=True)

    # if we got here, the JSON was syntactically correct
    # perform semantic sanity checks on the input
    if 'csp-report' not in output:
        return 'CSP report missing', 400
    for item in ['blocked-uri', 'document-uri', 'violated-directive']:
        if item not in output['csp-report']:
            return 'CSP report incomplete\n', 400

    output['owner_id'] = owner_id

    # add document identifier; this is important for performance
    # otherwise py-couchdb will add a random one
    output['_id'] = doc_id_generator.gen_id(owner_id)

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

    db.save(output, batch=True)

    return '', 204, []


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=8088)
