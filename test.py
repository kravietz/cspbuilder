#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pycouchdb.exceptions import NotFound

__author__ = 'Paweł Krawczyk'

import unittest
import time

try:
    import ujson as json
except ImportError:
    import json

import random
from apihelpers.known import KnownList
from apihelpers.utils import ClientResolver, DocIdGen, get_reports_db
from flask import Request
import pycouchdb
import requests


__author__ = 'Paweł Krawczyk'

TEST_ID1 = '1' * 20
TEST_ID2 = '2' * 20
TEST_ID3 = '3' * 20
TEST_ID4 = '4' * 20
CSP_DB = 'csp'
BASE_URL = 'http://localhost:8088'

REPORTS = [
    {"csp-report": {  # blocked URI approved by wildcard rule #1 (img-src & https:)
                      "document-uri": "https://www.example.com/", "blocked-uri": "https://assets.example.com",
                      "debug-code": 0, "violated-directive": "img-src 'self'"
                      }, "expect": "accept"},
    {"csp-report": {  # blocked URI approved by explicit rule #2 (script-src & URI)
                      "document-uri": "https://www.example.com/", "blocked-uri": "https://assets.example.com",
                      "debug-code": 0, "violated-directive": "script-src 'self'"
                      }, "expect": "accept"},
    {"csp-report": {  # blocked URI has explicit KL "reject" entry #3
                      "document-uri": "https://www.example.com/", "blocked-uri": "https://evil.com",
                      "debug-code": 0, "violated-directive": "frame-src 'self'"
                      }, "expect": "reject"},
    {"csp-report": {  # blocked URI and type is not covered by any KL rule
                      "document-uri": "https://www.wtf.guru/", "blocked-uri": "http://wtf.info",
                      "debug-code": 0, "violated-directive": "img-src 'self'"
                      }, "expect": "unknown"},
    {"csp-report": {  # blocked URI and document URI are the same, should be allowed by "self" rule #4
                      "document-uri": "http://www.wtf.com/", "blocked-uri": "http://www.wtf.com/test.html",
                      "debug-code": 0, "violated-directive": "style-src 'self'"
                      }, "expect": "accept"},
    {"csp-report": {  # blocked URI is literal "self", should be allowed by rule #4
                      "document-uri": "https://www.wtf.com/", "blocked-uri": "self",
                      "debug-code": 0, "violated-directive": "style-src 'self'"
                      }, "expect": "accept"},
    {"csp-report": {  # blocked URI should be allowed by explicit rule #5 with hostname wildcard
                      "document-uri": "http://www.example.com/",
                      "blocked-uri": "https://images.wildcard.com/some/image.jpg",
                      "debug-code": 0, "violated-directive": "img-src 'self'"
                      }, "expect": "accept"},
    {"csp-report": {  # blocked URI has different schema, should not match #5
                      "document-uri": "http://www.example.com/",
                      "blocked-uri": "http://images.wildcard.com/some/image.jpg",
                      "debug-code": 0, "violated-directive": "img-src 'self'"
                      }, "expect": "unknown"},
    {"csp-report": {  # empty blocked-uri should be matched by #5
                      "document-uri": "http://www.example.com/", "blocked-uri": "null",
                      "debug-code": 0, "violated-directive": "script-src 'self'"
                      }, "expect": "accept"},
    {"csp-report": {  # should not be matched by #6 because of different type (object-src vs script-src)
                      "document-uri": "http://www.example.com/", "blocked-uri": "null",
                      "debug-code": 0, "violated-directive": "object-src 'self'"
                      }, "expect": "unknown"},

]

KL = [
    {"owner_id": TEST_ID1, "review_action": "accept", "_id": "KLRULE1",  # 1
     "review_type": "img-src", "review_source": "https:"},
    {"owner_id": TEST_ID1, "review_action": "accept", "_id": "KLRULE2",  # 2
     "review_type": "script-src", "review_source": "https://assets.example.com"},
    {"owner_id": TEST_ID1, "review_action": "reject", "_id": "KLRULE3",  # 3
     "review_type": "frame-src", "review_source": "https://evil.com"},
    {"owner_id": TEST_ID1, "review_action": "accept", "_id": "KLRULE4",  # 4
     "review_type": "style-src", "review_source": "'self'"},
    {"owner_id": TEST_ID1, "review_action": "accept", "_id": "KLRULE5",  # 5
     "review_type": "img-src", "review_source": "https://*.wildcard.com"},
    {"owner_id": TEST_ID1, "review_action": "accept", "_id": "KLRULE6",  # 6
     "review_type": "script-src", "review_source": "'unsafe-inline'"},

    {"owner_id": TEST_ID2, "review_action": "accept", "_id": "KLRULE7",  # irrelevant rule 7
     "review_type": "script-src", "review_source": "'unsafe-eval'"},
]


class TestKnownList(unittest.TestCase):
    def setUp(self):
        self.csp_db = pycouchdb.Server().database(CSP_DB)

        # load the known list
        for kl in KL:
            self.csp_db.save(kl)
        self.kl = KnownList(self.csp_db)

    def test_kl(self):
        for rep in REPORTS:
            expect = rep['expect']
            report = rep['csp-report']
            self.assertEqual(self.kl.decision(TEST_ID1, report)['action'], expect,
                             'Expected "{}" on: {}'.format(expect, report))
            self.assertEqual(self.kl.decision("other id", report)['action'], "unknown",
                             'Expected "{}" on: {}'.format("unknown", report))

    def tearDown(self):
        # need to clean up so that other tests don't get Conflict exception
        for kl in KL:
            self.csp_db.delete(kl['_id'])


class TestClassifier(unittest.TestCase):
    def setUp(self):
        # initial request required initialise the database for TEST_ID1
        self.test_id = TEST_ID1
        self.report_url = 'http://localhost:8088/report/{}/'.format(self.test_id)
        self.headers = {'content-type': 'application/csp-report'}

        # init the reports db for TEST_ID1
        requests.post(BASE_URL + '/api/{}/init'.format(self.test_id))

        # prepare databases for direct checks
        self.reports_db = pycouchdb.Server().database(get_reports_db(self.test_id))
        self.csp_db = pycouchdb.Server().database('csp')

        # upload the test known list - this will be used by classifier.py
        for kl in KL:
            self.csp_db.save(kl)
        self.kl = KnownList(self.csp_db)

        time.sleep(1)

        # send a "ping" report to make classifier update the KL on next call
        report = REPORTS[-1]
        report['csp-report']['debug-code'] = 'ping-only'
        requests.post(self.report_url, data=json.dumps(report), headers=self.headers)

        time.sleep(1)

        self.doc_id_generator = DocIdGen(self.csp_db)

    # helper function to check classification status for given report
    # directly in the database
    def _get_classification(self, testval):
        response = None

        for item in self.reports_db.query('reports/1200_all', key=self.test_id, include_docs=True):
            doc = item['doc']
            if 'csp-report' in doc:
                report = doc['csp-report']
                if report.get('debug-code') == testval:
                    # obtain review from the report's meta section
                    try:
                        response = doc['review']['decision']
                    except KeyError:
                        print('No review found in doc=', doc)
        return response

    def test_classify_single(self):
        report = REPORTS[0]
        testval = random.randint(0, 10000)
        report['csp-report']['debug-code'] = testval
        self.r = requests.post(self.report_url, data=json.dumps(report), headers=self.headers)
        self.assertTrue(self.r.ok, self.r.status_code)

        time.sleep(1)

        # check if the report was classified as accepted
        result = self._get_classification(testval)
        self.assertTrue(result, report['expect'])

    def test_classify_many(self):
        for report in REPORTS:
            testval = random.randint(0, 10000)
            report['csp-report']['debug-code'] = testval
            self.r = requests.post(self.report_url, data=json.dumps(report), headers=self.headers)
            self.assertTrue(self.r.ok, self.r.status_code)

            time.sleep(1)

            # check if the report was classified as accepted
            result = self._get_classification(testval)
            self.assertTrue(result, report['expect'])

    def tearDown(self):
        # need to clean up so that other tests don't get Conflict exception
        for kl in KL:
            self.csp_db.delete(kl['_id'])


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
        # initial request required initialise the database for TEST_ID4
        self.test_id = TEST_ID4
        self.reports_url = 'http://localhost:8088/report/{}/'.format(TEST_ID4)
        self.headers = {'content-type': 'application/csp-report'}

        # init the reports db for TEST_ID1
        requests.post(BASE_URL + '/api/{}/init'.format(self.test_id))

        self.csp_db = pycouchdb.Server().database(CSP_DB)
        self.reports_db = pycouchdb.Server().database(get_reports_db(self.test_id))

        self.reports_url = 'http://localhost:8088/report/{}/'.format(self.test_id)
        self.report = {"_id": "this will be replaced by a random value",
                       "csp-report": {
                           "document-uri": "https://www.example.com/",
                           # match KL
                           "blocked-uri": "https://retro.com/test.swf",
                           # match KL
                           "violated-directive": "object-src 'self'"
                       },
                       # match KL
                       "owner_id": self.test_id,
                       "meta": {
                           "timestamp": "2014-12-17T16:03:12.248527+00:00",
                           "user_agent": "python-requests/2.5.0 CPython/3.4.1 Darwin/14.0.0",
                           "remote_geo": None,
                           "remote_ip": "127.0.0.1"
                       }
                       }
        # this KL rule should reclassify a previously unclassified report when added
        self.kl1 = {"owner_id": self.test_id, "review_action": "accept", "_id": "matching-rule",
                    "review_type": "object-src", "review_source": "https://retro.com"}
        # this KL rule is irrelevant to the report and should not result in classification
        self.kl2 = {"owner_id": TEST_ID2, "review_action": "accept", "_id": "non-matching-rule",
                    "review_type": "object-src", "review_source": "https://retro.com"}

    def test_retro(self):
        """
        A new report is added that should be classified as "unknown". Then a matching KL entry is added
        and the report should be reclassifed.
        """
        testval = str(random.randint(0, 10000))
        self.report['_id'] = testval
        # add report directly to reports database
        self.reports_db.save(self.report)
        # check that it's saved as unclassified
        self.doc = self.reports_db.get(testval)
        self.assertNotIn('review', self.doc)
        # now add KL rule to the 'csp' database
        self.csp_db.save(self.kl1)
        # check if the report was reclassified
        time.sleep(1)
        self.doc = self.reports_db.get(testval)
        self.assertIn('review', self.doc)
        self.assertEqual(self.doc['review']['decision'], 'accept')

    def test_no_kl(self):
        """
        Non-matching entry is added and the report should remain unclassified.
        """
        testval = str(random.randint(0, 10000))
        self.report['_id'] = testval
        # post message
        self.reports_db.save(self.report)
        # check that it's saved as unclassified
        self.doc = self.reports_db.get(testval)
        self.assertNotIn('review', self.doc)
        # now add an unrelated KL rule
        self.csp_db.save(self.kl2)
        # check if the report was reclassified - should not be
        time.sleep(1)
        self.doc = self.reports_db.get(testval)
        # it may be either that the report does not have 'review'
        # field at all, or the review is 'unknown'
        unknown = 'review' not in self.doc
        if 'review' in self.doc:
            unknown = self.doc['review']['decision'] == 'unknown'
        self.assertTrue(unknown)

    def tearDown(self):
        try:
            self.csp_db.delete(self.kl1['_id'])
            self.csp_db.delete(self.kl2['_id'])
        except NotFound:
            pass


class TestLocalApi(unittest.TestCase):
    def setUp(self):
        # initial request required initialise the database for TEST_ID3
        # a separate owner_id is used to avoid all kinds of conflicts with classifier/retro
        self.test_id = TEST_ID3
        self.url = 'http://localhost:8088/report/{}/'.format(self.test_id)
        self.report = REPORTS[0]
        self.headers = {'content-type': 'application/csp-report'}

        # init the reports db for TEST_ID1
        requests.post(BASE_URL + '/api/{}/init'.format(self.test_id))

        # prepare database for direct checks
        self.db = pycouchdb.Server().database(get_reports_db(self.test_id))

        self.doc_id_generator = DocIdGen(self.db)

    def _saved(self, testval):
        """
        This tests is report identified by testval was saved in the database. This
        is checked directly in the database
        """
        found = False
        for item in self.db.query('reports/1200_all', key=self.test_id, include_docs=True):
            if 'csp-report' in item['doc'] and item['doc']['csp-report'].get('debug-code') == testval:
                found = True
        return found

    def test_insert_single_report(self):
        """
        Test basic HTTP API -> database workflow. This does *not* test if the report was
        classified according to KL rules, as this requires a running classifier.
        """
        testval = random.randint(0, 10000)
        self.report["_id"] = self.doc_id_generator.new_id()
        self.report['csp-report']['debug-code'] = testval
        self.r = requests.post(self.url, data=json.dumps(self.report), headers=self.headers)
        self.assertTrue(self.r.ok)
        self.assertTrue(self._saved(testval))

    def test_insert_many_reports(self):
        num = 10
        vals = []
        for i in range(0, num):
            testval = random.randint(0, 10000)
            vals.append(testval)
            self.report['csp-report']['debug-code'] = testval
            self.r = requests.post(self.url, data=json.dumps(self.report), headers=self.headers)
            self.assertTrue(self.r.ok)
        for testval in vals:
            self.assertTrue(self._saved(testval), 'Document with id debug-code {} was not saved'.format(testval))

    def test_tagged_report(self):
        """
        This tests HTTP API insertion with tagged report.
        """
        expect_tag = 'tag-' + str(random.randint(0, 10000))
        url = 'http://localhost:8088/report/{}/{}/'.format(self.test_id, expect_tag)
        self.r = requests.post(url, data=json.dumps(self.report), headers=self.headers)
        self.assertTrue(self.r.ok)
        found = False
        for item in self.db.query('reports/1200_all', key=self.test_id, include_docs=True):
            if 'tag' in item['doc']['meta']:
                found_tag = item['doc']['meta']['tag']
                if found_tag == expect_tag:
                    found = True
        self.assertTrue(found)

    # these tests attempt to insert CSP reports invalid in many ways and are all
    # expected to fail

    def test_invalid_content_type(self):
        headers = {'content-type': 'text/plain'}
        self.r = requests.post(self.url, data=json.dumps(self.report), headers=headers)
        self.assertFalse(self.r.ok)

    def test_csp_report_missing(self):
        self.r = requests.post(self.url, data="", headers=self.headers)
        self.assertFalse(self.r.ok)

    def test_csp_report_empty_report(self):
        self.r = requests.post(self.url, data="{{{{{{{{", headers=self.headers)
        self.assertFalse(self.r.ok)

    def test_csp_report_invalid_json(self):
        self.r = requests.post(self.url, data="", headers=self.headers)
        self.assertFalse(self.r.ok)

    def test_invalid_method(self):
        self.r = requests.put(self.url, data=json.dumps(self.report), headers=self.headers)
        self.assertFalse(self.r.ok)

    def test_invalid_tag(self):
        invalid_tag = 'test{(\''
        url = 'http://localhost:8088/report/{}/{}/'.format(self.test_id, invalid_tag)
        self.r = requests.post(url, data=json.dumps(self.report), headers=self.headers)
        self.assertFalse(self.r.ok)


if __name__ == '__main__':
    unittest.main(warnings='ignore')  # avoid  ResourceWarning: unclosed <socket.socket
