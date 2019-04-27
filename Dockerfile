FROM perl:5-slim
COPY . /home/joomscan
WORKDIR /home/joomscan
RUN adduser joomscan --disabled-password --disabled-login --gecos "" --no-create-home --home /home/joomscan && chown joomscan:joomscan /home/joomscan -R
RUN apt-get update && apt-get install -y libc6-dev gcc libcrypt-ssleay-perl openssl libssl-dev libz-dev && rm /var/lib/apt/lists/* -R
RUN cpanm Bundle::LWP && cpanm LWP::Protocol::https
USER joomscan
ENTRYPOINT ["perl","joomscan.pl"]
CMD ["-h"]
