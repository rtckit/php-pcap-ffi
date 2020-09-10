FROM composer:1.10.10 as composer

WORKDIR /usr/src/php-pcap-ffi

COPY composer.* /usr/src/php-pcap-ffi/

RUN apk add libffi libffi-dev && \
  docker-php-ext-install ffi && \
  composer install --no-scripts --no-suggest --no-interaction --prefer-dist --optimize-autoloader

COPY . /usr/src/php-pcap-ffi

RUN composer dump-autoload --optimize --classmap-authoritative

FROM php:7.4-cli-alpine

RUN apk add bind-tools libffi libffi-dev libpcap && \
  docker-php-ext-install ffi sockets

WORKDIR /usr/src/php-pcap-ffi

COPY . /usr/src/php-pcap-ffi

COPY --from=composer /usr/src/php-pcap-ffi/vendor /usr/src/php-pcap-ffi/vendor

CMD ["php", "-i"]
