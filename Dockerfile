FROM unixorn/debian-py3
RUN mkdir -p /data && mkdir -p /config

COPY dist/*.whl /data
RUN pip install --no-cache-dir --disable-pip-version-check /data/*.whl

# Use bash -l so that we pick up the REQUESTS_CA_BUNDLE value from 
# /etc/profile.d/python-enable-all-ssl-certs.sh
CMD ["bash", "-l"]