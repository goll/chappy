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
$ curl -s -d 'data=foobar' http://127.0.0.1:8080/bcrypt
$2b$12$qQ6Nb7GbWp0VJ8XnhfWZ8epT1/3dh.JvY8Erh7PK7nZeUq/Ub6TDe

$ curl -s -d 'data=foobar' http://127.0.0.1:8080/sha256-crypt
$5$rounds=65536$ytlZKF9MFJvKkAoT$0Dm.w0qZ4O91XBkI5Ju.0U6y/nRejQtadwAx0HP8JCC

$ curl -s -d 'data=foobar' http://127.0.0.1:8080/sha512-crypt
$6$rounds=65536$hflF6IqhUG2oeCZc$0foP32AuJZaRh9yOeujmXfrKtGH1ewfUJGYT7g5hSnInOiaRJ/JssFGgyV2f3FfirmIrMHkYe9p25nC8j6w4z.
```

* Supports JSON output:
```
$ curl -s -d 'data=foobar' http://127.0.0.1:8080/bcrypt/json | jq
{
  "success": true,
  "hash": "$2b$12$K7zRmlNF0qOfUWMU/J48Ie3Q8tHu.IHtmIt6t5Ovu9yskW3smmDra",
  "algorithm": "bcrypt"
}

$ curl -s -d 'data=foobar' http://127.0.0.1:8080/sha256-crypt/json | jq
{
  "success": true,
  "hash": "$5$rounds=65536$Dzyh8Jr4sRCmbNzK$Xb30aTlBguskSb79S0SYjEvOyXQxkf7AU6kurh0ORf7",
  "algorithm": "sha256_crypt"
}

$ curl -s -d 'data=foobar' http://127.0.0.1:8080/sha512-crypt/json | jq
{
  "success": true,
  "hash": "$6$rounds=65536$KItaUa9JP3sWiDZE$VAIXqGnjIs29KMZ0AIB2wtUhcPzXL3iXYodZj5VgP8Czx.SwgUqqE/xOx4td3xnAZvyJqNWOgrG3hmZ2JOLzf0",
  "algorithm": "sha512_crypt"
}

```

## Supported endpoints
* hashlib:
  * `/md5`
  * `/sha1`
  * `/sha224`
  * `/sha256`
  * `/sha384`
  * `/sha512`

* passlib:
  * crypt:
    * `/bcrypt`
    * `/sha256-crypt`
    * `/sha512-crypt`
    * `/argon2`
    * `/bcrypt-sha256`
    * `/pbkdf2-sha256`
    * `/pbkdf2-sha512`
    * `/scrypt`
  * LDAP:
    * `/ldap-md5`
    * `/ldap-sha1`
    * `/ldap-salted-md5`
    * `/ldap-salted-sha1`
    * `/ldap-bcrypt`
    * `/ldap-sha256-crypt`
    * `/ldap-sha512-crypt`
  * GRUB 2:
    * `/grub2`
