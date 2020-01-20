FROM golang:1.12.4-alpine3.9 as base

RUN set -eux; \
	apk add --no-cache --virtual git

RUN apk add --update \
        bash \
        ca-certificates \
        tzdata

RUN mkdir -p /dev/net && \
    mknod -m 0666 /dev/net/tun c 10 200

RUN mkdir /app

# Build app
WORKDIR /go/src/app
COPY ./src/ .
RUN go get . && \
    CGO_ENABLED=0 go build -ldflags "-s -w" -o unpack-srv

FROM alpine:latest AS runtime

RUN apk add --update --no-cache openvpn

# Copy over user files so we can drop to least privledged user
COPY --from=base /etc/passwd /etc/passwd
COPY --from=base /app /app
COPY --from=base /go/src/app/unpack-srv /app/unpack-srv
COPY ./start-services.sh /app/start-services.sh
COPY ./vpn-profile.ovpn /app/profile.ovpn

# Explicitly pass in debug to force gin/proxy into debug mode
ENV GIN_MODE release

CMD ["sh", "/app/start-services.sh"]
EXPOSE 3000