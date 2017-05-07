# chappy
chappy is a crypto HTTP API implemented in Python 3 using [aiohttp](https://aiohttp.readthedocs.io/en/stable/) and [passlib](https://passlib.readthedocs.io/en/stable/index.html).

## Installation
* Clone the repo:
```
$ git clone https://github.com/goll/chappy.git && cd chappy/
```

* Create a virtualenv:
```
$ virtualenv venv
$ source venv/bin/activate
$ pip install -r requirements.txt
```

* Run chappy:
```
$ ./chappy.py
======== Running on http://127.0.0.1:8080 ========
(Press CTRL+C to quit)
```

* Happy hashing:
```
$ curl -s -d 'data=foobar' http://127.0.0.1:8080/sha512-crypt
$6$rounds=65536$hflF6IqhUG2oeCZc$0foP32AuJZaRh9yOeujmXfrKtGH1ewfUJGYT7g5hSnInOiaRJ/JssFGgyV2f3FfirmIrMHkYe9p25nC8j6w4z.
```

* Supports JSON output:
```
$ curl -s -d 'data=foobar' http://127.0.0.1:8080/sha512-crypt/json | jq
{
  "success": true,
  "hash": "$6$rounds=65536$KItaUa9JP3sWiDZE$VAIXqGnjIs29KMZ0AIB2wtUhcPzXL3iXYodZj5VgP8Czx.SwgUqqE/xOx4td3xnAZvyJqNWOgrG3hmZ2JOLzf0",
  "algorithm": "sha512_crypt"
}

```

## Supported endpoints
* hashlib:
  * /md5
  * /sha1
  * /sha224
  * /sha256
  * /sha384
  * /sha512
* crypt:
  * /bcrypt
  * /sha256-crypt
  * /sha512-crypt
  * /unix-disabled
  * /argon2
  * /bcrypt-sha256
  * /pbkdf2-sha256
  * /pbkdf2-sha512
  * /scrypt
* LDAP:
  * /ldap-md5
  * /ldap-sha1
  * /ldap-salted-md5
  * /ldap-salted-sha1
  * /ldap-bcrypt
  * /ldap-sha256-crypt
  * /ldap-sha512-crypt
  * /ldap-pbkdf2-sha256
  * /ldap-pbkdf2-sha512
* GRUB 2:
  * /grub2
