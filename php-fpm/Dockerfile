FROM composer AS composer
FROM mlocati/php-extension-installer AS php-extension-installer
FROM php:8.3-fpm

COPY --from=composer /usr/bin/composer /usr/bin/composer
COPY --from=php-extension-installer /usr/bin/install-php-extensions /usr/local/bin/

RUN set -xe && \
    apt-get update && \
    apt-get -y upgrade && \
    apt-get install -y --no-install-recommends \
      bash \
      git \
      nano \
      wget \
      zip && \
    install-php-extensions \
      xdebug \
      zip
