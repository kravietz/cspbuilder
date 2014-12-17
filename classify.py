#!/usr/bin/env python
# -*- coding: utf-8 -*-
import pycouchdb

__author__ = 'Paweł Krawczyk'

database = pycouchdb.Server().database('csp_test')


def callback(message, db=None):
    try:
        doc = db.get(message['id'])
    except KeyError:
        print('ERROR', doc)
        return

    if 'review_type' in doc:
        print(doc)


while True:
    database.changes_feed(callback)