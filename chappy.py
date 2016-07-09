#!/usr/bin/env python3.5
# -*- coding: utf-8 -*-

import hashlib
import aiohttp
from aiohttp import web
from passlib import hash

def hashlib_view_factory(algorithm):

    async def handler(request):

        if request.method == 'POST':
            await request.post()
            data = request.POST.get('data')
            if len(data) > 64:
                return web.json_response({'success': False, 'reason': 'data is longer than 64 characters'})
        elif request.method == 'GET':
            data = request.GET.get('data')
            if len(data) > 64:
                return web.json_response({'success': False, 'reason': 'data is longer than 64 characters'})
        else:
            return web.json_response({'success': False, 'reason': 'method not allowed'})

        if data is None:
            return web.json_response({'success': False, 'reason': 'missing data parameter'})

        hash_class = getattr(hashlib, algorithm)
        hc = hash_class()
        hc.update(data.encode('utf-8'))

        return web.json_response({'success': True, 'hash': hc.hexdigest(), 'algorithm': algorithm })

    return handler

def passlib_view_factory(algorithm, **kwds):

    async def handler(request):

        if request.method == 'POST':
            await request.post()
            data = request.POST.get('data')
            if len(data) > 64:
                return web.json_response({'success': False, 'reason': 'data is longer than 64 characters'})
        elif request.method == 'GET':
            data = request.GET.get('data')
            if len(data) > 64:
                return web.json_response({'success': False, 'reason': 'data is longer than 64 characters'})
        else:
            return web.json_response({'success': False, 'reason': 'method not allowed'})

        if data is None:
            return web.json_response({'success': False, 'reason': 'missing data parameter'})

        hash_function = getattr(hash, algorithm)

        return web.json_response({'success': True, 'hash': hash_function.encrypt(data.encode('utf-8'), **kwds), 'algorithm': algorithm })

    return handler

app = web.Application()

# hashlib
app.router.add_route('*', '/md5.json', hashlib_view_factory('md5'))
app.router.add_route('*', '/sha1.json', hashlib_view_factory('sha1'))
app.router.add_route('*', '/sha224.json', hashlib_view_factory('sha224'))
app.router.add_route('*', '/sha256.json', hashlib_view_factory('sha256'))
app.router.add_route('*', '/sha384.json', hashlib_view_factory('sha384'))
app.router.add_route('*', '/sha512.json', hashlib_view_factory('sha512'))

# crypt
app.router.add_route('*', '/shadow.json', passlib_view_factory('sha512_crypt', rounds=65536))
app.router.add_route('*', '/htpasswd.json', passlib_view_factory('apr_md5_crypt'))
app.router.add_route('*', '/md5-crypt.json', passlib_view_factory('md5_crypt'))
app.router.add_route('*', '/bcrypt.json', passlib_view_factory('bcrypt'))
app.router.add_route('*', '/sha1-crypt.json', passlib_view_factory('sha1_crypt', rounds=65536))
app.router.add_route('*', '/sha256-crypt.json', passlib_view_factory('sha256_crypt', rounds=65536))
app.router.add_route('*', '/sha512-crypt.json', passlib_view_factory('sha512_crypt', rounds=65536))
app.router.add_route('*', '/apr-md5-crypt.json', passlib_view_factory('apr_md5_crypt'))
app.router.add_route('*', '/bcrypt-sha256.json', passlib_view_factory('bcrypt_sha256'))
app.router.add_route('*', '/pbkdf2-sha1.json', passlib_view_factory('pbkdf2_sha1', rounds=65536))
app.router.add_route('*', '/pbkdf2-sha256.json', passlib_view_factory('pbkdf2_sha256'))
app.router.add_route('*', '/pbkdf2-sha512.json', passlib_view_factory('pbkdf2_sha512'))

# LDAP
app.router.add_route('*', '/ldap.json', passlib_view_factory('ldap_sha512_crypt', rounds=65536))
app.router.add_route('*', '/ldap-md5.json', passlib_view_factory('ldap_md5'))
app.router.add_route('*', '/ldap-sha1.json', passlib_view_factory('ldap_sha1'))
app.router.add_route('*', '/ldap-salted-md5.json', passlib_view_factory('ldap_salted_md5'))
app.router.add_route('*', '/ldap-salted-sha1.json', passlib_view_factory('ldap_salted_sha1'))
app.router.add_route('*', '/ldap-md5-crypt.json', passlib_view_factory('ldap_md5_crypt'))
app.router.add_route('*', '/ldap-bcrypt.json', passlib_view_factory('ldap_bcrypt'))
app.router.add_route('*', '/ldap-sha1-crypt.json', passlib_view_factory('ldap_sha1_crypt', rounds=65536))
app.router.add_route('*', '/ldap-sha256-crypt.json', passlib_view_factory('ldap_sha256_crypt', rounds=65536))
app.router.add_route('*', '/ldap-sha512-crypt.json', passlib_view_factory('ldap_sha512_crypt', rounds=65536))
app.router.add_route('*', '/ldap-hex-md5.json', passlib_view_factory('ldap_hex_md5'))
app.router.add_route('*', '/ldap-hex-sha1.json', passlib_view_factory('ldap_hex_sha1'))
app.router.add_route('*', '/ldap-pbkdf2-sha1.json', passlib_view_factory('ldap_pbkdf2_sha1', rounds=65536))
app.router.add_route('*', '/ldap-pbkdf2-sha256.json', passlib_view_factory('ldap_pbkdf2_sha256'))
app.router.add_route('*', '/ldap-pbkdf2-sha512.json', passlib_view_factory('ldap_pbkdf2_sha512'))

# GRUB
app.router.add_route('*', '/grub.json', passlib_view_factory('md5_crypt'))
app.router.add_route('*', '/grub2.json', passlib_view_factory('grub_pbkdf2_sha512'))

# Django
app.router.add_route('*', '/django-bcrypt.json', passlib_view_factory('django_bcrypt'))
app.router.add_route('*', '/django-pbkdf2-sha1.json', passlib_view_factory('django_pbkdf2_sha1', rounds=65536))
app.router.add_route('*', '/django-pbkdf2-sha256.json', passlib_view_factory('django_pbkdf2_sha256'))

if __name__ == '__main__':

    web.run_app(app)
