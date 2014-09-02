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

    client_ip = environ.get('REMOTE_ADDR')
    request_method = environ.get('REQUEST_METHOD')

    # sanity checks
    # check HTTP method
    if request_method != 'POST':
        print('Error: invalid request method {} from {}'.format(client_ip, request_method))
        return http_400_bad_request(start_response, "Invalid HTTP method")

    # get identifier of page sending this report
    request_uri = environ.get('REQUEST_URI')
    try:
        page_id = int(request_uri.split('/')[2])
    except (ValueError, IndexError, AttributeError):
        print('Error: bad report URI {} from {}'.format(request_uri, client_ip))
        return http_400_bad_request(start_response)

    content_type = environ.get('CONTENT_TYPE')

    # check content type
    if content_type not in ALLOWED_CONTENT_TYPES:
        print('Error: invalid content type {} from {}'.format(content_type, request_method))
        return http_400_bad_request(start_response, "Invalid content type")

    # check body size
    request_body_size = int(environ.get('CONTENT_LENGTH', 0))
    if request_body_size == 0:
        print('Error: empty request body from {}'.format(client_ip))
        return http_400_bad_request(start_response, "Empty body")

    # get body content and try JSON decode
    request_body = environ['wsgi.input'].read(request_body_size)
    try:
        output = json.loads(request_body.decode('ascii'))
    except ValueError:
        print('Error: invalid JSON from {}: {}'.format(client_ip, request_body))
        return http_400_bad_request(start_response, "Invalid JSON")

    # check if csp-report is present in JSON
    if not 'csp-report' in output:
        print('Error: JSON from {} has no csp-report: {}'.format(client_ip, request_body))
        return http_400_bad_request(start_response, "Csp-report object missing")

    output['owner_id'] = page_id

    # fill-in metadata for current report from HTTP headers
    meta = {}

    # User-Agent header
    user_agent = environ.get('HTTP_USER_AGENT')
    if user_agent:
        meta['user_agent'] = user_agent

    # save client's IP address
    meta['remote_ip'] = client_ip

    # UTC timestamp
    meta['timestamp'] = datetime.now(timezone.utc).isoformat()

    # copy metadata into the final report object
    output['meta'] = meta

    # save current report to CouchDB
    db = couchdb.Server(COUCHDB_SERVER)['csp']
    db.save(output)

    print('{} {} {} {}'.format(meta['timestamp'], client_ip, request_uri, output['csp-report']['blocked-uri']))

    return http_204_no_content(start_response)
