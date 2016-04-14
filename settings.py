#!/usr/bin/env python
# -*- coding: utf-8 -*-
import socket

__author__ = 'Paweł Krawczyk'

ALLOWED_CONTENT_TYPES = ['application/json', 'application/csp-report']
CSRF_KEY = 'PtwRT6oQn8EEgH+onjf/9FDmB1Y'
DEVELOPER_MACHINE = socket.gethostname().endswith('.lan')
CLASSIFY_INTERVAL = 200
