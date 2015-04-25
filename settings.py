#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys

__author__ = 'Paweł Krawczyk'

ALLOWED_CONTENT_TYPES = ['application/json', 'application/csp-report']
CSRF_KEY = 'fxwL8Ole62zSUXOk8LYKQlMweLs'
DEVELOPER_MACHINE = sys.gethostname().endswith('.lan')