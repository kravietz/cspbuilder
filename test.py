#!/usr/bin/env python
# -*- coding: utf-8 -*-
import unittest
import json
import random
import time

import pycouchdb
import requests


__author__ = 'pawelkrawczyk'

TEST_ID = '732349358731880803'
DB = 'csp_test'

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

KL = '''
{
   "owner_id": "732349358731880803",
   "timestamp": "2014-12-12T22:47:39.491204+00:00",
   "review_method": "user",
   "client_ip": "2.98.46.7",
   "review_action": "accept",
   "review_type": "script-src",
   "review_source": "https://assets.example.com"
}
'''


def db_clean(db):
    for item in db.query('csp/1200_all', include_docs=True):
        if not item['id'].startswith('_design'):
            db.delete(item['doc'])


class TestPublicApi(unittest.TestCase):
    def setUp(self):
        self.hostname = 'cspbuilder.info'
        self.https_url = 'http://{}/report/{}/'.format(self.hostname, TEST_ID)
        self.http_url = 'http://{}/report/{}/'.format(self.hostname, TEST_ID)
        self.report = json.loads(REPORT)

    def test_valid_post_https(self):
        headers = {'content-type': 'application/csp-report'}
        self.r = requests.post(self.https_url, data=json.dumps(self.report), headers=headers)
        self.assertTrue(self.r.ok)
        self.assertEqual(self.r.status_code, 204)

    def test_valid_post_http(self):
        headers = {'content-type': 'application/csp-report'}
        self.r = requests.post(self.http_url, data=json.dumps(self.report), headers=headers)
        self.assertTrue(self.r.ok)
        self.assertEqual(self.r.status_code, 204)

    def test_couchdb(self):
        self.r = requests.get(
            'https://{}/csp/_design/csp/_view/1900_unique_sites?limit=101&group=true'.format(self.hostname))
        self.assertTrue(self.r.ok)

    def test_https_redirect(self):
        self.r = requests.get('http://{}/'.format(self.hostname))
        self.assertTrue(self.r.ok)
        self.assertEqual(self.r.url, 'https://cspbuilder.info/static/#/main/')

    def test_unattended_login(self):
        self.r = requests.get('https://{}/policy/{}/'.format(self.hostname, TEST_ID))
        self.assertTrue(self.r.ok)
        self.assertEquals(len(self.r.history), 1)
        self.assertEqual(self.r.history[0].status_code, 302)
        self.assertIn('XSRF-TOKEN', self.r.history[0].cookies)
        self.assertIn('owner_id', self.r.history[0].cookies)
        self.assertEqual(self.r.history[0].cookies['owner_id'], TEST_ID)


class TestLocalApi(unittest.TestCase):
    def setUp(self):
        self.db = pycouchdb.Server().database(DB)
        self.url = 'http://localhost:8088/report/{}/'.format(TEST_ID)
        self.report = json.loads(REPORT)
        self.db.save(json.loads(KL))

    def _saved(self, testval):
        found = False
        for item in self.db.query('csp/1200_all', key=TEST_ID, include_docs=True):
            if 'csp-report' in item['doc'] and item['doc']['csp-report']['status-code'] == testval:
                found = True
        return found

    def _accepted(self, testval):
        found = False
        for item in self.db.query('csp/1200_all', key=TEST_ID, include_docs=True):
            if 'csp-report' in item['doc'] and item['doc']['csp-report']['status-code'] == testval and item['doc'][
                'reviewed'] == 'accepted':
                found = True
        return found

    def test_insert_single_report(self):
        headers = {'content-type': 'application/csp-report'}
        testval = random.randint(0, 10000)
        self.report['csp-report']['status-code'] = testval
        self.r = requests.post(self.url, data=json.dumps(self.report), headers=headers)
        self.assertTrue(self.r.ok)
        self.assertTrue(self._saved(testval))
        self.assertTrue(self._accepted(testval))

    def test_insert_many_reports(self):
        headers = {'content-type': 'application/csp-report'}
        num = 100
        vals = []
        for i in range(0, num):
            testval = random.randint(0, 10000)
            vals.append(testval)
            self.report['csp-report']['status-code'] = testval
            self.r = requests.post(self.url, data=json.dumps(self.report), headers=headers)
            self.assertTrue(self.r.ok)
        time.sleep(1)  # allow to update indexes
        for testval in vals:
            self.assertTrue(self._saved(testval), 'Document with id status-code {} was not saved'.format(testval))
            self.assertTrue(self._accepted(testval))

    def test_invalid_content_type(self):
        headers = {'content-type': 'text/plain'}
        self.r = requests.post(self.url, data=json.dumps(self.report), headers=headers)
        self.assertFalse(self.r.ok)
    
    def test_csp_report_missing(self):
        headers = {'content-type': 'application/csp-report' }
        self.r = requests.post(self.url, data="", headers=headers)
        self.assertFalse(self.r.ok)

    def test_csp_report_invalid_json(self):
        headers = {'content-type': 'application/csp-report' }
        self.r = requests.post(self.url, data="{}",  headers=headers)
        self.assertFalse(self.r.ok)
    
    def test_invalid_method(self):
        headers = {'content-type': 'application/csp-report' }
        self.r = requests.put(self.url, data=json.dumps(self.report), headers=headers)
        self.assertFalse(self.r.ok)


if __name__ == '__main__':
    unittest.main(warnings='ignore')  # avoid  ResourceWarning: unclosed <socket.socket
