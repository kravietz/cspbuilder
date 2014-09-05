#!/usr/bin/env python
# -*- coding: utf-8 -*-
import configparser
import os
from flask import Flask
from couchdb import Server

__author__ = 'pawelkrawczyk'

config = configparser.ConfigParser()
config.read(('collector.ini', os.path.join('collector', 'collector.ini'),
             os.path.join('..', 'collector', 'collector.ini')))

COUCHDB_SERVER = config.get('collector', 'couchdb_server')

app = Flask(__name__)
server = Server('http://localhost:5984/')
db = server['csp']

# TODO: set & verify CSRF headers
@app.route('/api/<owner_id>/all-reports', methods=['DELETE'])
def delete_all_reports(owner_id):
    docs = []
    for row in db.view('all_by_owner', key=owner_id, include_docs=True):
        doc = row.doc
        doc['_deleted'] = True
        docs.append(doc)
    print(db.update(docs))

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)