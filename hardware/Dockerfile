FROM ubuntu:19.04

RUN sed -i 's|http://archive.ubuntu.com/ubuntu/|http://old-releases.ubuntu.com/ubuntu/|g' /etc/apt/sources.list \
    && sed -i 's|http://security.ubuntu.com/ubuntu/|http://old-releases.ubuntu.com/ubuntu/|g' /etc/apt/sources.list \
    && apt-get update \
    && apt-get -y upgrade \
    && apt-get -y install openssl python2 socat

RUN groupadd -g 1337 user; \
    useradd -g 1337 -u 1337 -m user

COPY serverside/* /home/user/

RUN chmod 0555 /home/user/flagrom; \
    chmod 0444 /home/user/firmware.8051; \
    chmod 0444 /home/user/flag.txt

USER user
CMD socat TCP-LISTEN:1337,reuseaddr,fork EXEC:"/home/user/flagrom",pty,stderr
