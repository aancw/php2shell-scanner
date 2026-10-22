FROM php:8.3.35-apache

# A throwaway SSH target for testing the ssh mode of php2shell-scanner.
# It runs the vulnerable PHP release 8.3.35 with mod_php.
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /root/.ssh /run \
 && chmod 700 /root/.ssh \
 && ssh-keygen -A

COPY start-sshd.sh /usr/local/bin/start-sshd
COPY www/index.php /var/www/html/index.php
COPY php/zz-lab-fixture.ini /usr/local/etc/php/conf.d/zz-lab-fixture.ini
COPY sshd-password.conf /etc/ssh/sshd_config.d/99-lab-password.conf
RUN chmod +x /usr/local/bin/start-sshd

EXPOSE 22
CMD ["/usr/local/bin/start-sshd"]
