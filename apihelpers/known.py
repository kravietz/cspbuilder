#!/usr/bin/env python
# -*- coding: utf-8 -*-
import datetime

from fnmatch import fnmatch
import re


__author__ = 'Paweł Krawczyk'


def _base_uri_match(a, b):
    """
    Compare origin of two URLs to check if they both come from the same origin.
    :param a: first URL
    :param b: second URL
    :return: True or False
    """
    r = re.match(r"^(https?://[^?#/]+)", a)
    if not r:
        return False
    a = r.group(1)

    r = re.match(r"^(https?://[^?#/]+)", b)
    if not r:
        return False
    b = r.group(1)

    return a == b


def _match(pattern, report):
    match = False
    blocked_uri = report['blocked-uri']
    # null URLs can be matched by either inline or eval entries, per limitation of CSP 1.0
    if blocked_uri == 'null' and pattern in ["'unsafe-inline'", "'unsafe-eval'"]:
        match = True
    # self type matches
    if pattern == "'self'":
        # blocked URL matching document domain
        if _base_uri_match(blocked_uri, report['document-uri']):
            match = True
        # literal "self" entry in report
        if blocked_uri == "self":
            match = True
    # finally check the blocked URL pattern
    # because fnmatch() is used this should also cover typical CSP wildcards
    # http://image.wildcard.com/some/image.jpg vs http://*.wildcard.com -> MATCH
    # http://image.wildcard.com/some/image.jpg vs https://*.wildcard.com -> NO MATCH
    if fnmatch(blocked_uri, pattern + '*'):
        match = True

    return match


class KnownList(object):
    """
    Class that represents an in-memory copy of the CspBuilder's known list
    for run time processing. The list has the following structure:

    { 'owner_id1': {
            'script-src': {
                'http://source1': {
                    'action': 'accept', 'rule': '050ebaacbce4fff26f1f4f785ee2a097'
                },
                'https://source2': { ... },
            },
            'img-src': {
                ...
            },
            ...
        },
      'owner_id2': ...
    }

    Patterns for given owner and resource type are extracted with a dictionary lookup
    of ['owner_id']['type'] and then matched in a loop to handle wildcards.
    """
    last_update = None
    db = None
    known_list = {}

    def __len__(self):
        i = 0
        for owner_id in self.known_list.keys():
            for source_type in self.known_list[owner_id].keys():
                for _ in self.known_list[owner_id][source_type].keys():
                    i += 1
        return i

    def __str__(self):
        owner_ids = 0
        source_types = 0
        origins = 0
        for owner_id in self.known_list.keys():
            owner_ids += 1
            for source_type in self.known_list[owner_id].keys():
                source_types += 1
                for _ in self.known_list[owner_id][source_type].keys():
                    origins += 1
        return '<KnownList object: {} owner_ids, {} source_types, {} origins>'.format(owner_ids, source_types, origins)

    def add(self, rule_id, owner_id, rtype, origin, action):
        """
        Add a new row to the in-memory copy of the known list.
        Does not affect the master copy in the database.
        """
        # add list entry
        if owner_id not in self.known_list:
            self.known_list[owner_id] = {}
        if rtype not in self.known_list[owner_id]:
            self.known_list[owner_id][rtype] = {}
        self.known_list[owner_id][rtype][origin] = {'action': action, 'rule': rule_id}

    def load(self):
        """
        Load all known list entries from master copy in database
        and build a tree-like dictionary structure for fast lookups.
        """
        for row in self.db.query('csp/1000_known_list', include_docs=True):
            rule_id = row['id']
            owner_id = row['key']
            # ["script-src", "https://assets.example.com", "accept"]
            rtype = row['value'][0]
            origin = row['value'][1]
            action = row['value'][2]
            self.add(rule_id, owner_id, rtype, origin, action)

        if self.auto_update:
            self.last_update = datetime.datetime.now(datetime.timezone.utc)

    def __init__(self, db, interval=30, auto_update=True, verbose=False):
        self.auto_update = auto_update
        if self.auto_update:
            self.update_interval = datetime.timedelta(seconds=interval)
        self.db = db
        self.verbose = verbose
        self.load()
        self.last_update = datetime.datetime.now(datetime.timezone.utc)

    def decision(self, owner_id, report):
        """
        Takes a list composed of owner id, resource type and resource origin and returns an action for that
        set.

        :param report: CSP report in JSON
        :return: decision dictionary {'action: action, 'rule': rule identifier}
                 where action is 'accept', 'reject' or 'unknown'
                 and rule identifier is document id or None
        """
        # refresh the local KL copy if auto update interval has expired
        if self.auto_update and datetime.datetime.now(datetime.timezone.utc) - self.last_update > self.update_interval:
            self.load()
            if self.verbose:
                print('Self-updated', self)

        blocked_uri = report['blocked-uri']
        # effective-directive is CSP 1.1 http://www.w3.org/TR/CSP11/#violation-report-effective-directive
        if 'effective-directive' in report:
            rtype = report['effective-directive']
        # if not found, fall back to CSP 1.0 violated-directive
        else:
            rtype = report['violated-directive'].split(' ')[0]

        # try exact match
        try:
            decision = self.known_list[owner_id][rtype][blocked_uri]
            return decision
        except KeyError:
            pass

        try:
            for pattern, decision in self.known_list[owner_id][rtype].items():
                if _match(pattern, report):
                    return decision
        except KeyError:
            pass

        return {'action': 'unknown', 'rule': None}

