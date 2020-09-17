# This file is intended solely to facilitate development specific processes
REPOSITORY=rtckit/php-pcap-ffi-dev
RUN_CMD=docker run --name php-pcap-ffi-dev --rm -it -v `pwd`/reports:/usr/src/php-pcap-ffi/reports:rw ${REPOSITORY}
RUN_PHP_CMD=${RUN_CMD} php -d memory_limit=-1

image:
	docker build -t ${REPOSITORY} .

test: image
	${RUN_PHP_CMD} -d memory_limit=-1 ./vendor/bin/phpunit --debug

cover: image
	rm -rf reports/coverage
	${RUN_PHP_CMD} ./vendor/bin/phpunit --coverage-text --coverage-html=reports/coverage

stan: image
	${RUN_PHP_CMD} ./vendor/bin/phpstan analyse -n -vvv --ansi --level=max src

psalm: image
	${RUN_PHP_CMD} ./vendor/bin/psalm --show-info=true

test-ffi-scope: image
	${RUN_PHP_CMD} -d ffi.preload=./src/pcap.h -d memory_limit=-1 ./vendor/bin/phpunit --debug

buster:
	docker build -t ${REPOSITORY}:buster -f Dockerfile.buster .

buster-test: buster
	${RUN_CMD}:buster php -d memory_limit=-1 -d memory_limit=-1 ./vendor/bin/phpunit --debug

ci: stan psalm test-ffi-scope test buster-test

clean:
	rm -rf `cat .gitignore`
