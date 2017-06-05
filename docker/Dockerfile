from alpine

COPY yesdns /usr/local/bin/yesdns

# Default HTTP port is 5380
# By convention, the 'default' resolver is on 53
EXPOSE 53 5380

ENTRYPOINT yesdns