# This file is intended solely to facilitate development specific processes
REPOSITORY=rtckit/php-pcap-ffi-dev
RUN_CMD=docker run --name php-pcap-ffi-dev --rm -it  -v `pwd`/reports:/usr/src/php-pcap-ffi/reports:rw ${REPOSITORY}
RUN_PHP_CMD=${RUN_CMD} php -d memory_limit=-1

image:
	docker build -t ${REPOSITORY} .

local-image:
	docker build -v `pwd`:/usr/src/php-pcap-ffi:rw -t ${REPOSITORY} .

run: image
	${RUN_CMD}

test: image
	${RUN_PHP_CMD} -d memory_limit=-1 ./vendor/bin/phpunit --debug

cover:
	rm -rf reports/coverage
	${RUN_PHP_CMD} ./vendor/bin/phpunit --coverage-text --coverage-html=reports/coverage

stan:
	${RUN_PHP_CMD} ./vendor/bin/phpstan analyse -n -vvv --ansi --level=max src

psalm:
	${RUN_PHP_CMD} ./vendor/bin/psalm --show-info=true

check: stan psalm

clean:
	rm -rf `cat .gitignore`
