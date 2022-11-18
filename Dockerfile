FROM unixorn/debian-py3
ARG application_version=0.0
LABEL maintainer="Joe Block <jblock@zscaler.com>"
LABEL description="jira-commands tooling on a debian bullseye base"
LABEL version=${application_version}

RUN mkdir -p /data && mkdir -p /config

COPY dist/*.whl /data
RUN pip install --no-cache-dir --disable-pip-version-check /data/*.whl

# Use bash -l so that we pick up the REQUESTS_CA_BUNDLE value from 
# /etc/profile.d/python-enable-all-ssl-certs.sh
CMD ["bash", "-l"]