# PHP Packet Capture via FFI

Stream driven PHP packet capture library, leveraging libpcap via FFI.

[![Build Status](https://travis-ci.com/rtckit/php-pcap-ffi.svg?branch=master)](https://travis-ci.com/rtckit/php-pcap-ffi)
[![Latest Stable Version](https://poser.pugx.org/rtckit/pcap-ffi/v/stable.png)](https://packagist.org/packages/rtckit/pcap-ffi)
[![Maintainability](https://api.codeclimate.com/v1/badges/e8c2dca80074553ba561/maintainability)](https://codeclimate.com/github/rtckit/php-pcap-ffi/maintainability)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

## Pcap Extension

Whenever possible (or if using an older version of PHP), you should use the native [pcap PHP extension](https://github.com/rtckit/php-pcap-ext), this library is provided as an alternative to it for select/edge cases. Otherwise, the FFI based packet capture library is fully compatible with the `pcap` extension. As a result, all changes applied to the extension are reflected here too, and the library version will always match its extension counterpart.

## Requirements

This library makes use of features introduced as of PHP 7.4, it will not work with obsolete versions. Of course, the [PHP FFI extension](https://www.php.net/manual/en/book.ffi.php) must be installed and enabled.

The libpcap library must be installed on the target environment; some Linux distributions meddle with the library naming protocols and this can confuse the FFI initialization process. Should that be the case, one can set the `LIBPCAP_NAME` environment variable to the actual library name, or even the absolute path to the library's .so file for custom builds or non-standard directory layouts.

For example, for Debian Buster, one would set `LIBPCAP_NAME` to `libpcap.so.1.8.1`.

## Install

The recommended way to install this library is [through Composer](https://getcomposer.org). [New to Composer?](https://getcomposer.org/doc/00-intro.md)

This will install the latest supported version:

```sh
composer require rtckit/pcap-ffi:^0.6.5
```

## Tests

Before running the test suite, make sure the user has the ability to capture network packets (root or `CAP_NET_RAW`).

```sh
make test
```

## License

MIT, see [LICENSE file](LICENSE).

### Acknowledgments

* [libpcap](https://github.com/the-tcpdump-group/libpcap) by The Tcpdump Group, BSD licensed.

### Contributing

Bug reports (and small patches) can be submitted via the [issue tracker](https://github.com/rtckit/php-pcap-ffi/issues). Forking the repository and submitting a Pull Request is preferred for substantial patches.
