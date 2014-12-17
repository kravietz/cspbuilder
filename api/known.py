#!/usr/bin/env python
# -*- coding: utf-8 -*-
import datetime
from fnmatch import fnmatch

from api.utils import base_uri_match


__author__ = 'Paweł Krawczyk'


class KnownList(object):
    last_update = None
    db = None
    known_list = {}

    def _load(self):
        """
        Load all known list entries from database and build a tree-like dictionary structure
        for fast lookups.
        """
        for row in self.db.query('csp/1000_known_list', include_docs=True):
            owner_id = row['key']

            # ["script-src", "https://assets.example.com", "accept"]
            rtype = row['value'][0]
            origin = row['value'][1]
            action = row['value'][2]

            # add list entry
            if owner_id not in self.known_list:
                self.known_list[owner_id] = {}
            if type not in self.known_list[owner_id]:
                self.known_list[owner_id][rtype] = {}
            self.known_list[owner_id][rtype][origin] = action

        self.last_update = datetime.datetime.now(datetime.timezone.utc)

    def __init__(self, db):
        self.db = db
        self._load()

    @staticmethod
    def _match(pattern, report):

        match = False
        blocked_uri = report['blocked-uri']
        # null URLs can be matched by either inline or eval entries, per limitation of CSP 1.0
        if blocked_uri == 'null' and pattern in ["'unsafe-inline'", "'unsafe-eval'"]:
            match = True
        # self type matches
        if pattern == "'self'":
            # blocked URL matching document domain
            if base_uri_match(blocked_uri, report['document-uri']):
                match = True
            # literal "self" entry in report
            if blocked_uri == "self":
                match = True
        # finally the blocked URL pattern
        if fnmatch(blocked_uri, pattern + '*'):
            match = True

        return match

    def decision(self, owner_id, report):
        """
        Takes a list composed of owner id, resource type and resource origin and returns an action for that
        set.

        :param triplet: Example: ["732349358731880803", "script-src", "https://assets.example.com"]
        :return: decision string 'accept', 'reject' or 'unknown'
        """
        if datetime.datetime.now(datetime.timezone.utc) - self.last_update > datetime.timedelta(minutes=5):
            self._load()

        blocked_uri = report['blocked-uri']
        rtype = report['violated-directive'].split(' ')[0]

        # try exact match
        try:
            decision = self.known_list[owner_id][rtype][blocked_uri]
            return decision
        except KeyError:
            pass

        decision = 'unknown'

        for pattern, action in self.known_list[owner_id][rtype].items():
            print('Trying "{}" on {}'.format(pattern, blocked_uri))
            if self._match(pattern, report):
                decision = action
                break

        return decision
