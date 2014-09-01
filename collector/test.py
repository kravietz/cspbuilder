#!/usr/bin/env python
# -*- coding: utf-8 -*-
import configparser
import unittest
from couchdb.design import ViewDefinition
import requests
import couchdb
import os
import random

__author__ = 'pawelkrawczyk'

config = configparser.ConfigParser()
config.read(('collector.ini', os.path.join('collector', 'collector.ini')))

CSP_BODY = config.get('test', 'csp_body')
SITE_URL = config.get('test', 'site_url')
COUCHDB_SERVER = config.get('collector', 'couchdb_server')


CSP_SOURCE_DIRECTIVES = [
        'default-src',
        'script-src',
        'style-src',
        'img-src',
        'connect-src',
        'font-src',
        'object-src',
        'media-src',
        'frame-src', ]

MAP1 = """
function(doc) {
  if(doc['owner_id'] && doc['csp-report'] && doc['csp-report']['blocked-uri'] && doc['csp-report']['violated-directive']) {
  emit( [ doc['owner_id'],
          doc['csp-report']['blocked-uri'],
         doc['csp-report']['violated-directive'].split(' ')[0] ],
	 null );
 }
}
"""
REDUCE1 = """
function(k,v,re) { return true; }
"""

MAP2 = """
function(doc) {
  if(doc['owner_id'] && doc['csp-report'] && doc['meta']) {
  emit( doc['owner_id'], null );
 }
}
"""

class TestCspCollection(unittest.TestCase):

    def setUp(self):
        self.couch = couchdb.Server(COUCHDB_SERVER)
        self.db = self.couch['csp']
        i = 0
        for doc in self.db:
            del self.db[doc]
            i += 1

    def test_client(self):
        headers = {'content-type': 'application/csp-report' }
        self.r = requests.post(SITE_URL, data=CSP_BODY, headers=headers)
        self.assertTrue(self.r.ok)

    def test_doc(self):
        headers = {'content-type': 'application/csp-report' }
        self.r = requests.post(SITE_URL, data=CSP_BODY, headers=headers)
        self.assertTrue(self.r.ok)
        # but more importantly, check if reports were added
        self.assertGreater(len(self.db), 0)

    def test_content_type(self):
        headers = {'content-type': 'text/plain' }
        self.r = requests.post(SITE_URL, data=CSP_BODY, headers=headers)
        self.assertFalse(self.r.ok)

    def test_csp_report_missing(self):
        headers = {'content-type': 'application/csp-report' }
        self.r = requests.post(SITE_URL, data="", headers=headers)
        self.assertFalse(self.r.ok)

    def test_csp_report_invalid(self):
        headers = {'content-type': 'application/csp-report' }
        self.r = requests.post(SITE_URL, data="{}", headers=headers)
        self.assertFalse(self.r.ok)

    def test_method(self):
        self.r = requests.get(SITE_URL)
        self.assertFalse(self.r.ok)

    @classmethod
    def tearDownClass(self):
        headers = {'content-type': 'application/csp-report' }
        for i in range(1,30):
            report=CSP_BODY.replace('script-src', random.choice(CSP_SOURCE_DIRECTIVES))
            report=report.replace('http://cdn.shorte.st', random.choice(['http://cdn.shorte.st','http://ipsec.pl','http://echelon.pl','http://google.com']))
            site_url=SITE_URL.replace('9018643792216450862', random.choice(['111','222','221','333']))
            self.r = requests.post(site_url, data=report, headers=headers)

        db = couchdb.Server(COUCHDB_SERVER)['csp']
        ViewDefinition('csp', 'sources_key_owner', map_fun=MAP1, reduce_fun=REDUCE1).sync(db)
        ViewDefinition('csp', 'all_by_owner', map_fun=MAP2).sync(db)


if __name__ == '__main__':
    unittest.main(warnings='ignore') # avoid  ResourceWarning: unclosed <socket.socket
