#!/usr/bin/env python
# -*- coding: utf-8 -*-
import unittest
import time

try:
    import ujson as json
except ImportError:
    import json

import random
from api.known import KnownList
from api.utils import ClientResolver, DocIdGen
from flask import Request
import pycouchdb
import requests


__author__ = 'Paweł Krawczyk'

TEST_ID = '732349358731880803'
DB = 'csp'

REPORTS = [
    {"csp-report": {  # blocked URI approved by wildcard rule #1 (img-src & https:)
                      "document-uri": "https://www.example.com/", "blocked-uri": "https://assets.example.com",
                      "status-code": 0, "violated-directive": "img-src 'self'"
    }, "expect": "accept"},
    {"csp-report": {  # blocked URI approved by explicit rule #2 (script-src & URI)
                      "document-uri": "https://www.example.com/", "blocked-uri": "https://assets.example.com",
                      "status-code": 0, "violated-directive": "script-src 'self'"
    }, "expect": "accept"},
    {"csp-report": {  # blocked URI has explicit KL "reject" entry #3
                      "document-uri": "https://www.example.com/", "blocked-uri": "https://evil.com",
                      "status-code": 0, "violated-directive": "frame-src 'self'"
    }, "expect": "reject"},
    {"csp-report": {  # blocked URI and type is not covered by any KL rule
                      "document-uri": "https://www.wtf.guru/", "blocked-uri": "http://wtf.info",
                      "status-code": 0, "violated-directive": "img-src 'self'"
    }, "expect": "unknown"},
    {"csp-report": {  # blocked URI and document URI are the same, should be allowed by "self" rule #4
                      "document-uri": "http://www.wtf.com/", "blocked-uri": "http://www.wtf.com/test.html",
                      "status-code": 0, "violated-directive": "style-src 'self'"
    }, "expect": "accept"},
    {"csp-report": {  # blocked URI is literal "self", should be allowed by rule #4
                      "document-uri": "https://www.wtf.com/", "blocked-uri": "self",
                      "status-code": 0, "violated-directive": "style-src 'self'"
    }, "expect": "accept"},
    {"csp-report": {  # blocked URI should be allowed by explicit rule #5 with hostname wildcard
                      "document-uri": "http://www.example.com/",
                      "blocked-uri": "https://images.wildcard.com/some/image.jpg",
                      "status-code": 0, "violated-directive": "img-src 'self'"
    }, "expect": "accept"},
    {"csp-report": {  # blocked URI has different schema, should not match #5
                      "document-uri": "http://www.example.com/",
                      "blocked-uri": "http://images.wildcard.com/some/image.jpg",
                      "status-code": 0, "violated-directive": "img-src 'self'"
    }, "expect": "unknown"},
    {"csp-report": {  # empty blocked-uri should be matched by #5
                      "document-uri": "http://www.example.com/", "blocked-uri": "null",
                      "status-code": 0, "violated-directive": "script-src 'self'"
    }, "expect": "accept"},
    {"csp-report": {  # should not be matched by #6 because of different type (object-src vs script-src)
                      "document-uri": "http://www.example.com/", "blocked-uri": "null",
                      "status-code": 0, "violated-directive": "object-src 'self'"
    }, "expect": "unknown"},

]

KL = [
    {"owner_id": "732349358731880803", "review_action": "accept", "_id": "RULE 111",  # 1
     "review_type": "img-src", "review_source": "https:"},
    {"owner_id": "732349358731880803", "review_action": "accept", "_id": "RULE 222",  # 2
     "review_type": "script-src", "review_source": "https://assets.example.com"},
    {"owner_id": "732349358731880803", "review_action": "reject", "_id": "RULE 333",  # 3
     "review_type": "frame-src", "review_source": "https://evil.com"},
    {"owner_id": "732349358731880803", "review_action": "accept", "_id": "RULE 444",  # 4
     "review_type": "style-src", "review_source": "'self'"},
    {"owner_id": "732349358731880803", "review_action": "accept", "_id": "RULE 555",  # 5
     "review_type": "img-src", "review_source": "https://*.wildcard.com"},
    {"owner_id": "732349358731880803", "review_action": "accept", "_id": "RULE 666",  # 6
     "review_type": "script-src", "review_source": "'unsafe-inline'"},
]


def db_clean(db):
    for item in db.query('csp/1200_all', include_docs=True):
        if not item['id'].startswith('_design'):
            db.delete(item['doc'])


class TestKnownList(unittest.TestCase):
    def setUp(self):
        self.db = pycouchdb.Server().database(DB)
        db_clean(self.db)
        for kl in KL:
            self.db.save(kl)
        self.kl = KnownList(self.db)

    def test_kl(self):
        for rep in REPORTS:
            expect = rep['expect']
            report = rep['csp-report']
            self.assertEqual(self.kl.decision(TEST_ID, report)['action'], expect,
                             'Expected "{}" on: {}'.format(expect, report))
            self.assertEqual(self.kl.decision("other id", report)['action'], "unknown",
                             'Expected "{}" on: {}'.format("unknown", report))


class TestClientResolver(unittest.TestCase):
    def setUp(self):
        self.cr = ClientResolver()

    def test_cr_ip(self):
        self.req = Request({'REMOTE_ADDR': '8.8.8.8'})
        self.assertEqual(self.cr.get_ip(self.req), '8.8.8.8')

    def test_cr_ip_cf(self):
        self.req = Request({'HTTP_CF_CONNECTING_IP': '8.8.8.8', 'REMOTE_ADDR': '199.27.128.1'})
        self.assertEqual(self.cr.get_ip(self.req), '8.8.8.8')

    def test_cr_ip_geo(self):
        self.assertEqual(self.cr.get_geo(Request({'GEOIP_COUNTRY': 'USA'})), 'USA')

    def test_cr_ip_geo_cf(self):
        self.assertEqual(self.cr.get_geo(Request({'HTTP_CF_IPCOUNTRY': 'USA'})), 'USA')


class TestRetro(unittest.TestCase):
    def setUp(self):
        self.db = pycouchdb.Server().database(DB)
        db_clean(self.db)
        self.url = 'http://localhost:8088/report/{}/'.format(TEST_ID)
        self.report = {"_id": "ITEM 8888",
            "csp-report": {
                "document-uri": "https://www.example.com/",
                "blocked-uri": "https://retro.com/test.swf",
                "violated-directive": "object-src 'self'"
            },
            "meta": {
                "timestamp": "2014-12-17T16:03:12.248527+00:00",
                "user_agent": "python-requests/2.5.0 CPython/3.4.1 Darwin/14.0.0",
                "remote_geo": None,
                "remote_ip": "127.0.0.1"
            },
            "owner_id": "732349358731880803"}
        self.kl1 = {"owner_id": "732349358731880803", "review_action": "accept", "_id": "RULE 8888",
                    "review_type": "object-src", "review_source": "https://retro.com"}
        self.kl2 = {"owner_id": "111111111111111111", "review_action": "accept", "_id": "RULE 9999",
                    "review_type": "object-src", "review_source": "https://retro.com"}

    def test_retro(self):
        """
        A new report is added that should be classified as "unknown". Then a matching KL entry is added
        and the report should be reclassifed.
        """
        testval = str(random.randint(0, 10000))
        self.report['_id'] = testval
        # post message
        self.db.save(self.report)
        # check that it's saved as unclassified
        self.doc = self.db.get(testval)
        self.assertNotIn('review', self.doc)
        # now add KL rule
        self.db.save(self.kl1)
        # check if the report was reclassified
        time.sleep(1)
        self.doc = self.db.get(testval)
        self.assertIn('review', self.doc)
        self.assertEqual(self.doc['review']['decision'], 'accept')

    def test_no_kl(self):
        """
        Non-matching entry is added and the report should remain unclassified.
        """
        testval = str(random.randint(0, 10000))
        self.report['_id'] = testval
        # post message
        self.db.save(self.report)
        # check that it's saved as unclassified
        self.doc = self.db.get(testval)
        self.assertNotIn('review', self.doc)
        # now add KL rule
        self.db.save(self.kl2)
        # check if the report was reclassified
        time.sleep(1)
        self.doc = self.db.get(testval)
        unknown = 'review' in self.doc
        if 'review' in self.doc:
            unknown = self.doc['review']['decision'] == 'unknown'
        self.assertTrue(unknown)


class TestPublicApi(unittest.TestCase):
    def setUp(self):
        self.hostname = 'cspbuilder.info'
        self.https_url = 'http://{}/report/{}/'.format(self.hostname, TEST_ID)
        self.http_url = 'http://{}/report/{}/'.format(self.hostname, TEST_ID)
        self.report = REPORTS[0]

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
        db_clean(self.db)
        self.url = 'http://localhost:8088/report/{}/'.format(TEST_ID)
        self.doc_id_generator = DocIdGen()
        self.report = REPORTS[0]

    def _saved(self, testval):
        found = False
        for item in self.db.query('csp/1200_all', key=TEST_ID, include_docs=True):
            if 'csp-report' in item['doc'] and item['doc']['csp-report'].get('status-code') == testval:
                found = True
        return found

    def _accepted(self, testval):
        found = False
        for item in self.db.query('csp/1200_all', key=TEST_ID, include_docs=True):
            if 'csp-report' in item['doc'] and item['doc']['csp-report'].get('status-code') == testval \
                    and item['doc']['reviewed'] == 'accepted':
                found = True
        return found

    def test_insert_single_report(self):
        headers = {'content-type': 'application/csp-report'}
        testval = random.randint(0, 10000)
        self.report["_id"] = self.doc_id_generator.gen_id(TEST_ID)
        self.report['csp-report']['status-code'] = testval
        self.r = requests.post(self.url, data=json.dumps(self.report), headers=headers)
        self.assertTrue(self.r.ok)
        self.assertTrue(self._saved(testval))

    def test_insert_many_reports(self):
        headers = {'content-type': 'application/csp-report'}
        num = 10
        vals = []
        for i in range(0, num):
            testval = random.randint(0, 10000)
            vals.append(testval)
            self.report["_id"] = self.doc_id_generator.gen_id(TEST_ID)
            self.report['csp-report']['status-code'] = testval
            self.r = requests.post(self.url, data=json.dumps(self.report), headers=headers)
            self.assertTrue(self.r.ok)
        for testval in vals:
            self.assertTrue(self._saved(testval), 'Document with id status-code {} was not saved'.format(testval))

    def test_invalid_content_type(self):
        headers = {'content-type': 'text/plain'}
        self.r = requests.post(self.url, data=json.dumps(self.report), headers=headers)
        self.assertFalse(self.r.ok)

    def test_csp_report_missing(self):
        headers = {'content-type': 'application/csp-report'}
        self.r = requests.post(self.url, data="", headers=headers)
        self.assertFalse(self.r.ok)

    def test_csp_report_empty_report(self):
        headers = {'content-type': 'application/csp-report'}
        self.r = requests.post(self.url, data="{{{{{{{{", headers=headers)
        self.assertFalse(self.r.ok)

    def test_csp_report_invalid_json(self):
        headers = {'content-type': 'application/csp-report'}
        self.r = requests.post(self.url, data="", headers=headers)
        self.assertFalse(self.r.ok)

    def test_invalid_method(self):
        headers = {'content-type': 'application/csp-report'}
        self.r = requests.put(self.url, data=json.dumps(self.report), headers=headers)
        self.assertFalse(self.r.ok)


if __name__ == '__main__':
    unittest.main(warnings='ignore')  # avoid  ResourceWarning: unclosed <socket.socket
