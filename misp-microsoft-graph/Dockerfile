FROM python:3.10-alpine

WORKDIR /app
RUN apk add git && git clone https://github.com/microsoftgraph/security-api-solutions.git

WORKDIR /app/security-api-solutions/Samples/MISP
COPY . /src 
RUN python -m pip install --no-cache-dir install requests requests-futures pymisp && PYTHONHASHSEED=0
RUN echo "* * * * * python3 -u /app/security-api-solutions/Samples/MISP/script.py" > /etc/crontabs/root
CMD ["crond", "-l", "2", "-f"]
