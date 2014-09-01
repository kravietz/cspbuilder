#!/usr/bin/env python
# -*- coding: utf-8 -*-
import configparser
from datetime import datetime, timezone
import json
import couchdb
import os

__author__ = 'pawelkrawczyk'

def http_400_bad_request(start_response, reason=""):
    start_response('400 Bad Request', [('Content-Type', 'text/plain')])
    return [bytes(reason+'\n', 'ascii')]


def http_204_no_content(start_response):
    start_response('204 No Content', [])
    return []


config = configparser.ConfigParser()
config.read(('collector.ini', os.path.join('collector', 'collector.ini')))

COUCHDB_SERVER = config.get('collector', 'couchdb_server')
ALLOWED_CONTENT_TYPES = [x.strip() for x in config.get('collector', 'mime_types').split(',') ]


def application(environ, start_response):

    # sanity checks
    # check HTTP method
    if environ.get('REQUEST_METHOD') != 'POST':
        return http_400_bad_request(start_response, "Invalid HTTP method")

    # check content type
    if environ.get('CONTENT_TYPE') not in ALLOWED_CONTENT_TYPES:
        return http_400_bad_request(start_response, "Invalid content type")

    # check body size
    request_body_size = int(environ.get('CONTENT_LENGTH', 0))
    if request_body_size == 0:
        return http_400_bad_request(start_response, "Empty body")

    # get body content and try JSON decode
    request_body = environ['wsgi.input'].read(request_body_size)
    try:
        output = json.loads(request_body.decode('ascii'))
    except ValueError:
        return http_400_bad_request(start_response, "Invalid JSON")

    # check if csp-report is present in JSON
    if not 'csp-report' in output:
        return http_400_bad_request(start_response, "Csp-report object missing")

    # get identifier of page sending this report
    try:
        page_id = int(environ.get('REQUEST_URI').split('/')[2])
    except (ValueError, IndexError, AttributeError):
        return http_400_bad_request(start_response)

    output['owner_id'] = page_id

    # fill-in metadata for current report from HTTP headers
    meta = {}

    # User-Agent header
    user_agent = environ.get('HTTP_USER_AGENT')
    if user_agent:
        meta['user_agent'] = user_agent

    # client's IP address
    remote_ip = environ.get('REMOTE_ADDR')
    if remote_ip:
        meta['remote_ip'] = remote_ip

    # UTC timestamp
    meta['timestamp'] = datetime.now(timezone.utc).isoformat()

    # copy metadata into the final report object
    output['meta'] = meta

    # save current report to CouchDB
    db = couchdb.Server(COUCHDB_SERVER)['csp']
    print(db.save(output))

    return http_204_no_content(start_response)
