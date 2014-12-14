#!/usr/bin/env python
# -*- coding: utf-8 -*-
import unittest
import json
import random

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


class TestApi(unittest.TestCase):
    def setUp(self):
        self.server = pycouchdb.Server()
        self.db = self.server.database('csp')
        self.url = 'http://cspbuilder.info:8088/report/{}/'.format(TEST_ID)
        self.report = json.loads(REPORT)

    def _saved(self, testval):
        found = False
        for item in self.db.query('csp/1200_all', key=TEST_ID, include_docs=True):
            if item['doc']['csp-report']['status-code'] == testval:
                found = True
        return found

    def test_client(self):
        headers = {'content-type': 'application/csp-report'}
        testval = random.randint(0, 1000)
        self.report['csp-report']['status-code'] = testval
        self.r = requests.post(self.url, data=json.dumps(self.report), headers=headers)
        self.assertTrue(self.r.ok)
        self.assertTrue(self._saved(testval))

    def test_content_type(self):
        headers = {'content-type': 'text/plain' }
        self.r = requests.post(self.url, data=json.dumps(self.report), headers=headers)
        self.assertFalse(self.r.ok)
    
    def test_csp_report_missing(self):
        headers = {'content-type': 'application/csp-report' }
        self.r = requests.post(self.url, data="", headers=headers)
        self.assertFalse(self.r.ok)
    
    def test_csp_report_invalid(self):
        headers = {'content-type': 'application/csp-report' }
        self.r = requests.post(self.url, data="{}",  headers=headers)
        self.assertFalse(self.r.ok)
    
    def test_invalid_method(self):
        headers = {'content-type': 'application/csp-report' }
        self.r = requests.put(self.url, data=json.dumps(self.report), headers=headers)
        self.assertFalse(self.r.ok)

    @classmethod
    def tearDownClass(self):
        self.server = pycouchdb.Server()
        self.db = self.server.database('csp')
        for item in self.db.query('csp/1200_all', key=TEST_ID, include_docs=True):
            self.db.delete(item['id'])


if __name__ == '__main__':
    unittest.main(warnings='ignore')  # avoid  ResourceWarning: unclosed <socket.socket
