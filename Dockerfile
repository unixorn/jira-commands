FROM debian:11-slim
ARG application_version=0.0
LABEL maintainer="Joe Block <jblock@zscaler.com>"
LABEL description="jira-commands tooling on a debian bullseye base"
LABEL version=${application_version}

RUN mkdir -p /data && mkdir -p /config
RUN apt-get update && \
    apt-get install -y apt-utils ca-certificates --no-install-recommends && \
    apt-get upgrade -y --no-install-recommends && \
    update-ca-certificates && \
    apt-get install -y python3-pip python3-dev && \
    rm -fr /tmp/* /var/lib/apt/lists/*

COPY dist/*.whl /data
RUN pip install --no-cache-dir --disable-pip-version-check /data/*.whl

# Use bash -l so that we pick up the REQUESTS_CA_BUNDLE value from 
# /etc/profile.d/python-enable-all-ssl-certs.sh
CMD ["bash", "-l"]