ACME implementation in Ada
==========================

This is an
[Automatic Certificate Management Environment](https://tools.ietf.org/html/rfc8555)
client in Ada.

## Install
Unpack sources and run `make`.

### Dependencies
It depends on
 * [Matreshka](https://forge.ada-ru.org/matreshka) library.
 * [JWT](https://github.com/reznikmm/jwt) Ada library.
 * [AWS](https://github.com/AdaCore/aws) - Ada Web Server.

## Usage
To run the example:
* Generate account key pairs and Certificate Signing Request (CSR) using
 `openssl`:

```
openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 \
 -keyout /tmp/priv.key -out /dev/null -subj ""
grep -v ^- /tmp/priv.key | base64 -d > /tmp/priv.dat

openssl rsa -pubout -in /tmp/priv.key -outform DER -out /tmp/pub.dat

openssl req -nodes -newkey rsa:2048 -keyout /tmp/domain.key \
 -out /tmp/cert.csr -subj "/C=UA/CN=example.com"
grep -v "CERTIFICATE REQUEST" /tmp/cert.csr | base64 --decode > /tmp/csr.dat
```

* Run the example

```
.objs/hello_world/hello_world_run example.com
```

* If everything works fine, then you will get the certificate chain in
the output. The private key for the web server is in `/tmp/domain.key`.

## Maintainer

[@MaximReznik](https://github.com/reznikmm).

## Contribute

Feel free to dive in!
[Open an issue](https://github.com/reznikmm/acme-ada/issues/new)
or submit PRs.

## License

[MIT](LICENSES/MIT.txt) © Maxim Reznik
