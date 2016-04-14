#!/usr/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'Paweł Krawczyk'
import json
import unittest

import requests

from test import TEST_ID1, REPORTS


__author__ = 'Paweł Krawczyk'


class TestPublicApi(unittest.TestCase):
    def setUp(self):
        self.hostname = 'cspbuilder.info'
        self.https_url = 'https://{}/report/{}/'.format(self.hostname, TEST_ID1)
        self.http_url = 'http://{}/report/{}/'.format(self.hostname, TEST_ID1)
        self.init_url = 'https://{}/api/{}/init'.format(self.hostname, TEST_ID1)
        self.delete_url = 'https://{}/api/{}/all'.format(self.hostname, TEST_ID1)
        self.report = REPORTS[0]

    def test_couchdb(self):
        self.r = requests.get(
            'https://{}/csp/_design/csp/_view/1900_unique_sites?limit=101&group=true'.format(self.hostname))
        self.assertTrue(self.r.ok)

    def test_https_redirect(self):
        self.r = requests.get('http://{}/'.format(self.hostname))
        self.assertTrue(self.r.ok)
        self.assertEqual(self.r.url, 'https://cspbuilder.info/static/#/main/')

    def test_unattended_login(self):
        self.r = requests.get('https://{}/policy/{}/'.format(self.hostname, TEST_ID1))
        self.assertTrue(self.r.ok)
        self.assertEqual(len(self.r.history), 1)
        self.assertEqual(self.r.history[0].status_code, 302)
        self.assertIn('XSRF-TOKEN', self.r.history[0].cookies)
        self.assertIn('owner_id', self.r.history[0].cookies)
        self.assertEqual(self.r.history[0].cookies['owner_id'], TEST_ID1)

    # THESE WILL CREATE REPORTS ON THE SERVER

    def test_init(self):
        self.r = requests.post(self.init_url)
        self.assertTrue(self.r.ok)

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

    def test_delete_all(self):
        self.r = requests.delete(self.delete_url)
        self.assertTrue(self.r.ok)
        self.assertEqual(self.r.status_code, 204)
