#!/usr/bin/env python
# -*- coding: utf-8 -*-
import datetime

__author__ = 'Paweł Krawczyk'


class Quota(object):
    """
    Simple class for enforcing quota on number of reports for single owner id. Based
    on the 1900_unique_sites view that returns number of reports per id, the table
    is cached inside object and self-updates every 5 minutes.
    """
    quotas = {}
    limit = 1e6
    last_update = None
    db = None

    def _load(self):
        for row in self.db.query('csp/1900_unique_sites', group=True, group_level=1, reduce=True):
            owner_id = row['key'][0]
            count = row['value']
            if count > self.limit:
                self.quotas[owner_id] = True
            if owner_id in self.quotas and count < self.limit:
                del self.quotas[owner_id]
        self.last_update = datetime.datetime.now(datetime.timezone.utc)

    def __init__(self, db):
        self.db = db
        self._load()

    def check(self, owner_id):
        if datetime.datetime.now(datetime.timezone.utc) - self.last_update > datetime.timedelta(minutes=5):
            self._load()
        return owner_id in self.quotas
