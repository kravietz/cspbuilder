#!/usr/bin/env python
# -*- coding: utf-8 -*-
import unittest
import json

import pycouchdb
import requests


__author__ = 'pawelkrawczyk'

TEST_ID = '732349358731880803'

REPORT = '''
{ "csp-report": {
       "document-uri": "https://www.example.com/eyedea/eyeface",
       "referrer": "https://www.example.com/explore?page=6",
       "blocked-uri": "https://assets.example.com",
       "status-code": 0,
       "original-policy": "default-src 'self'",
       "violated-directive": "script-src 'self'"
   } }
'''


class TestCspCollection(unittest.TestCase):
    def setUp(self):
        self.server = pycouchdb.Server()
        self.db = self.server.database('csp')
        self.url = 'https://cspbuilder.info/report/{}/'.format(TEST_ID)
        self.report = json.loads(REPORT)

    def test_client(self):
        headers = {'content-type': 'application/csp-report'}
        self.report['csp-report']['status-code'] = 1
        self.r = requests.post(self.url, data=REPORT, headers=headers)
        self.assertTrue(self.r.ok)
        # ensure report was added
        for item in self.db.query('csp/1200_all', key=TEST_ID, include_docs=True):
            print(item)

    # def test_doc(self):
    # headers = {'content-type': 'application/csp-report' }
    #     self.r = requests.post(self.url, data=REPORT, headers=headers)
    #     self.assertTrue(self.r.ok)
    #     # but more importantly, check if reports were added
    #     self.assertGreater(len(self.db), 0)
    #
    # def test_content_type(self):
    #     headers = {'content-type': 'text/plain' }
    #     self.r = requests.post(SITE_URL, data=CSP_BODY, headers=headers)
    #     self.assertFalse(self.r.ok)
    #
    # def test_csp_report_missing(self):
    #     headers = {'content-type': 'application/csp-report' }
    #     self.r = requests.post(SITE_URL, data="", headers=headers)
    #     self.assertFalse(self.r.ok)
    #
    # def test_csp_report_invalid(self):
    #     headers = {'content-type': 'application/csp-report' }
    #     self.r = requests.post(SITE_URL, data="{}", headers=headers)
    #     self.assertFalse(self.r.ok)
    #
    # def test_method(self):
    #     self.r = requests.get(SITE_URL)
    #     self.assertFalse(self.r.ok)

    @classmethod
    def tearDownClass(self):
        for item in self.db.query('csp/1200_all', key=TEST_ID, include_docs=True):
            print(item)
            self.db.delete(item['id'])
            #self.server.delete('csptest')
            #headers = {'content-type': 'application/csp-report' }
            #for i in range(1,30):
            #    report=CSP_BODY.replace('script-src', random.choice(CSP_SOURCE_DIRECTIVES))
            #    report=report.replace('http://cdn.shorte.st', random.choice(['http://cdn.shorte.st','http://ipsec.pl','http://echelon.pl','http://google.com']))
            #    site_url=SITE_URL.replace('9018643792216450862', random.choice(['111','222','221','333']))
            #    self.r = requests.post(site_url, data=report, headers=headers)

            #db = couchdb.Server(COUCHDB_SERVER)['csp']
            #ViewDefinition('csp', 'sources_key_owner', map_fun=MAP1, reduce_fun=REDUCE1).sync(db)
            #ViewDefinition('csp', 'all_by_owner', map_fun=MAP2).sync(db)


if __name__ == '__main__':
    unittest.main(warnings='ignore')  # avoid  ResourceWarning: unclosed <socket.socket
