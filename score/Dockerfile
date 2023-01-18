FROM python:3.10-alpine

# Copy the connector
COPY src /opt/misp-score

# Install Python modules
# hadolint ignore=DL3003
RUN cd /opt/misp-score && \
    pip3 install --no-cache-dir -r requirements.txt

RUN echo "* * * * * python3 -u /opt/misp-score/main.py" > /etc/crontabs/root
# Expose and entrypoint
CMD ["crond", "-l", "2", "-f"]

#COPY entrypoint.sh /
#RUN chmod +x /entrypoint.sh
#ENTRYPOINT ["/entrypoint.sh"]