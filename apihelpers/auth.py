#!/usr/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'Paweł Krawczyk'
import hashlib
import hmac

from flask import make_response, redirect

from settings import CSRF_KEY, DEVELOPER_MACHINE


__author__ = 'Paweł Krawczyk'


def login_response(owner_id):
    """
    Perform actual login action which is currently limited to setting owner_id cookie
    and XSRF-TOKEN cookie.

    :param owner_id:
    :return:
    """
    token = hmac.new(bytes(CSRF_KEY, 'ascii'), bytes(owner_id, 'ascii'), hashlib.sha512).hexdigest()
    resp = make_response(redirect('/static/#/analysis'))
    resp.set_cookie('XSRF-TOKEN', token, secure=(not DEVELOPER_MACHINE))
    resp.set_cookie('owner_id', owner_id, secure=(not DEVELOPER_MACHINE))
    print('login_response setting token cookie {}'.format(token))
    return resp


def verify_csrf_token(req):
    """
    Utility function to verify CSRF token on API calls. Uses secret configured in .ini file
    and the owner_id from request.

    :return: True if token correct, False if incorrect
    """
    request_token = req.headers.get('X-XSRF-TOKEN')
    owner_id = req.cookies.get('owner_id')
    print('verify_csrf_token owner_id={} request_token={}'.format(owner_id, request_token))

    if not (owner_id or request_token):
        print('verify_csrf_token missing owner_id or request token')
        return False

    expected_token = hmac.new(bytes(CSRF_KEY, 'ascii'), bytes(owner_id, 'ascii'), hashlib.sha512).hexdigest()

    if hmac.compare_digest(request_token, expected_token):
        return True

    print('verify_csrf_token token mismatch expected_token={}'.format(expected_token))
    return False
