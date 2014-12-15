#!/usr/bin/env python
# -*- coding: utf-8 -*-
import unittest
import json
import random

import pycouchdb
import requests
from api.sbf import SBF


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


class TestSbf(unittest.TestCase):
    def setUp(self):
        self.server = pycouchdb.Server()
        self.db = self.server.database('csp')
        self.sbf = SBF(self.db, doc_id='test_bloom')
        self.report = json.loads(REPORT)

    def test_sbf_init(self):
        doc = self.db.get(self.sbf.doc_id)
        self.assertTrue(doc['_id'] == self.sbf.doc_id)
        self.assertGreater(len(self.db.get_attachment(doc, self.sbf.file_name)), 0)

    def test_sbf_add(self):
        self.assertFalse(self.sbf.f.add('test'))
        self.assertTrue(self.sbf.f.add('test'))
        self.assertTrue(self.sbf.f.add('test'))
        self.assertFalse(self.sbf.f.add('test2'))

    def test_sbf_in(self):
        self.assertFalse('test' in self.sbf.f)
        self.sbf.f.add('test')
        self.assertTrue('test' in self.sbf.f)

    def test_sbf_error_rate(self):
        falses = 0.0
        trues = 0.0
        # each value is unique but there will be 
        # apparent collisions because of SBF error rate
        for val in range(0,10000):
            ret = self.sbf.f.add(val)
            if ret:
                trues += 1
            else:
                falses += 1
        self.assertLessEqual(trues/falses, self.sbf.error_rate)

    def test_fields(self):
        falses = 0.0
        trues = 0.0
        for val in range(0,1000):
            self.report['csp-report']['status-code'] = val
            ret = self.sbf.f.add(json.dumps(self.report))
            if ret:
                trues += 1
            else:
                falses += 1
        self.assertGreater(falses, 900)
        self.assertGreater(self.sbf.f.count, 900)
        self.sbf.save()
        doc = self.db.get(self.sbf.doc_id)
        size = len(self.db.get_attachment(doc, self.sbf.file_name))
        # for 1000 items it will be around 4000 bytes
        self.assertGreater(size, 1000)


    def tearDown(self):
        self.server = pycouchdb.Server()
        self.db = self.server.database('csp')
        self.doc = self.db.get('test_bloom')
        self.db.delete(self.doc)


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
        self.server = pycouchdb.Server()
        self.db = self.server.database('csp')
        self.url = 'http://localhost:8088/report/{}/'.format(TEST_ID)
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
        headers = {'content-type': 'text/plain'}
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
