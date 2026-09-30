# End-to-end test environment: MariaDB, WP-CLI and real WordPress sites.
#
#   docker build -t wp-secmon-test -f tests/integration/Dockerfile .
#   docker run --rm wp-secmon-test
#
# EL8 / PHP 7.4 (the CloudLinux/cPanel family): tests/integration/Dockerfile.el8
#
# The test builds the phar, installs it, then runs it.
# Needs network access (WordPress core, plugins, checksums and vulnerability data).
FROM debian:bookworm-slim

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      php-cli php-mysql php-curl php-xml php-mbstring php-zip mariadb-server mariadb-client \
      ca-certificates curl less procps \
 && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL -o /usr/local/bin/wp https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar \
 && chmod 755 /usr/local/bin/wp \
 && curl -fsSL https://wordpress.org/latest.tar.gz | tar xz -C /opt \
 && mv /opt/wordpress /opt/wp-core

COPY . /src
CMD ["php", "/src/tests/integration/run.php"]
