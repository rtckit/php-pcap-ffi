FROM composer:1.10.16 as composer

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

# Build and install pcov
ARG PHP_PCOV_RELEASE=3546be8
RUN cd /tmp && \
  curl https://codeload.github.com/krakjoe/pcov/tar.gz/$PHP_PCOV_RELEASE | tar xvz && \
  cd /tmp/pcov-$PHP_PCOV_RELEASE && \
  apk --no-cache add $PHPIZE_DEPS && \
  phpize && \
  ./configure && \
  make && \
  make install && \
  echo "extension=pcov.so" > /usr/local/etc/php/conf.d/pcov.ini
# Remove build dependencies
RUN apk --purge del $PHPIZE_DEPS && \
  rm -rf /tmp/*

WORKDIR /usr/src/php-pcap-ffi

COPY . /usr/src/php-pcap-ffi

COPY --from=composer /usr/src/php-pcap-ffi/vendor /usr/src/php-pcap-ffi/vendor

CMD ["php", "-i"]
