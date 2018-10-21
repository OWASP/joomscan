# Author: Mostafa Hussein (mostafa.hussein91@gmail.com)
FROM perl:5-slim
COPY . /home/joomscan
WORKDIR /home/joomscan
RUN adduser joomscan --disabled-password --disabled-login --gecos "" --no-create-home --home /home/joomscan && chown joomscan:joomscan /home/joomscan -R
RUN apt-get update && apt-get install -y --no-install-recommends libc6-dev=2.24-11+deb9u3 gcc=4:6.3.0-4 && rm /var/lib/apt/lists/* -R && cpanm Bundle::LWP
USER joomscan
ENTRYPOINT ["perl", "joomscan.pl"]
CMD ["-h"]
