#!/usr/bin/env python3.5
# -*- coding: utf-8 -*-

import hashlib
from aiohttp import web
from passlib import hash


def text_or_json(is_json=False, data_dict=None):

    if data_dict is None:
        data_dict = {}

    if is_json:

        return web.json_response(data_dict)

    else:
        body = "{}".format(data_dict['hash'] if data_dict['success'] else data_dict['reason'])

        return web.Response(body=body.encode('utf-8'))


def hashlib_view_factory(algorithm):

    async def handler(request):

        is_json = False

        if 'json' in request.path[-4:]:
            is_json = True

        if request.method == 'POST':
            await request.post()
            data = request.POST.get('data')

            if data is not None and len(data) > 64:

                return text_or_json(is_json, {'success': False, 'reason': 'data is longer than 64 characters'})

        elif request.method == 'GET':
            data = request.GET.get('data')

            if data is not None and len(data) > 64:

                return text_or_json(is_json, {'success': False, 'reason': 'data is longer than 64 characters'})

        else:

            return text_or_json(is_json, {'success': False, 'reason': 'method not allowed'})

        if data is None:

            return text_or_json(is_json, {'success': False, 'reason': 'missing data parameter'})

        hash_class = getattr(hashlib, algorithm)
        hc = hash_class()
        hc.update(data.encode('utf-8'))

        return text_or_json(is_json, {
            'success': True,
            'hash': hc.hexdigest(),
            'algorithm': algorithm
        })

    return handler


def passlib_view_factory(algorithm, **kwds):

    async def handler(request):

        is_json = False

        if 'json' in request.path[-4:]:
            is_json = True

        if request.method == 'POST':
            await request.post()
            data = request.POST.get('data')

            if data is not None and len(data) > 64:

                return text_or_json(is_json, {'success': False, 'reason': 'data is longer than 64 characters'})

        elif request.method == 'GET':
            data = request.GET.get('data')

            if data is not None and len(data) > 64:

                return text_or_json(is_json, {'success': False, 'reason': 'data is longer than 64 characters'})

        else:

            return text_or_json(is_json, {'success': False, 'reason': 'method not allowed'})

        if data is None:

            return text_or_json(is_json, {'success': False, 'reason': 'missing data parameter'})

        hash_function = getattr(hash, algorithm)

        return text_or_json(is_json, {
            'success': True,
            'hash': hash_function.encrypt(data.encode('utf-8'), **kwds),
            'algorithm': algorithm
        })

    return handler

app = web.Application()


def add_html_and_json_route(methods, path, views):

    if path[-1] != '/':
        json_path = "{}/json".format(path)
    else:
        json_path = "{}json".format(path)

    app.router.add_route(methods, path, views)
    app.router.add_route(methods, json_path, views)

# hashlib
add_html_and_json_route('*', '/md5', hashlib_view_factory('md5'))
add_html_and_json_route('*', '/sha1', hashlib_view_factory('sha1'))
add_html_and_json_route('*', '/sha224', hashlib_view_factory('sha224'))
add_html_and_json_route('*', '/sha256', hashlib_view_factory('sha256'))
add_html_and_json_route('*', '/sha384', hashlib_view_factory('sha384'))
add_html_and_json_route('*', '/sha512', hashlib_view_factory('sha512'))

# crypt
add_html_and_json_route('*', '/shadow', passlib_view_factory('sha512_crypt', rounds=65536))
add_html_and_json_route('*', '/htpasswd', passlib_view_factory('apr_md5_crypt'))
add_html_and_json_route('*', '/md5-crypt', passlib_view_factory('md5_crypt'))
add_html_and_json_route('*', '/bcrypt', passlib_view_factory('bcrypt'))
add_html_and_json_route('*', '/sha1-crypt', passlib_view_factory('sha1_crypt', rounds=65536))
add_html_and_json_route('*', '/sha256-crypt', passlib_view_factory('sha256_crypt', rounds=65536))
add_html_and_json_route('*', '/sha512-crypt', passlib_view_factory('sha512_crypt', rounds=65536))
add_html_and_json_route('*', '/apr-md5-crypt', passlib_view_factory('apr_md5_crypt'))
add_html_and_json_route('*', '/bcrypt-sha256', passlib_view_factory('bcrypt_sha256'))
add_html_and_json_route('*', '/pbkdf2-sha1', passlib_view_factory('pbkdf2_sha1', rounds=65536))
add_html_and_json_route('*', '/pbkdf2-sha256', passlib_view_factory('pbkdf2_sha256'))
add_html_and_json_route('*', '/pbkdf2-sha512', passlib_view_factory('pbkdf2_sha512'))

# LDAP
add_html_and_json_route('*', '/ldap', passlib_view_factory('ldap_sha512_crypt', rounds=65536))
add_html_and_json_route('*', '/ldap-md5', passlib_view_factory('ldap_md5'))
add_html_and_json_route('*', '/ldap-sha1', passlib_view_factory('ldap_sha1'))
add_html_and_json_route('*', '/ldap-salted-md5', passlib_view_factory('ldap_salted_md5'))
add_html_and_json_route('*', '/ldap-salted-sha1', passlib_view_factory('ldap_salted_sha1'))
add_html_and_json_route('*', '/ldap-md5-crypt', passlib_view_factory('ldap_md5_crypt'))
add_html_and_json_route('*', '/ldap-bcrypt', passlib_view_factory('ldap_bcrypt'))
add_html_and_json_route('*', '/ldap-sha1-crypt', passlib_view_factory('ldap_sha1_crypt', rounds=65536))
add_html_and_json_route('*', '/ldap-sha256-crypt', passlib_view_factory('ldap_sha256_crypt', rounds=65536))
add_html_and_json_route('*', '/ldap-sha512-crypt', passlib_view_factory('ldap_sha512_crypt', rounds=65536))
add_html_and_json_route('*', '/ldap-hex-md5', passlib_view_factory('ldap_hex_md5'))
add_html_and_json_route('*', '/ldap-hex-sha1', passlib_view_factory('ldap_hex_sha1'))
add_html_and_json_route('*', '/ldap-pbkdf2-sha1', passlib_view_factory('ldap_pbkdf2_sha1', rounds=65536))
add_html_and_json_route('*', '/ldap-pbkdf2-sha256', passlib_view_factory('ldap_pbkdf2_sha256'))
add_html_and_json_route('*', '/ldap-pbkdf2-sha512', passlib_view_factory('ldap_pbkdf2_sha512'))

# GRUB
add_html_and_json_route('*', '/grub', passlib_view_factory('md5_crypt'))
add_html_and_json_route('*', '/grub2', passlib_view_factory('grub_pbkdf2_sha512'))

# Django
add_html_and_json_route('*', '/django-bcrypt', passlib_view_factory('django_bcrypt'))
add_html_and_json_route('*', '/django-pbkdf2-sha1', passlib_view_factory('django_pbkdf2_sha1', rounds=65536))
add_html_and_json_route('*', '/django-pbkdf2-sha256', passlib_view_factory('django_pbkdf2_sha256'))

if __name__ == '__main__':

    web.run_app(app)
