###############################################################
# Dockerfile
# This is the Dockerfile for a release of Ghidra. 
# It should be built from the root directory of 
# a ghidra release using the command 
# docker build -f docker/Dockerfile -t <image-name>
###############################################################
FROM alpine:3.20 AS base

LABEL org.opencontainers.image.title="ghidra" \
	org.opencontainers.image.description="Docker image for Ghidra" \
	org.opencontainers.image.source="https://github.com/NationalSecurityAgency/ghidra" \
	org.opencontainers.image.licenses="Apache 2.0"

# Configure user, entrypoint, and some env vars first, before making the image larger with dependencies
# so that we can keep the image size as small as possible.
RUN addgroup -g 1001 -S ghidra && adduser -u 1001 -S ghidra -G ghidra
ENTRYPOINT ["/bin/bash", "/ghidra/docker/entrypoint.sh"]
# Set JAVA_HOME so that we don't need to do this manually when Ghidra is first started.
ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk
ENV LD_LIBRARY_PATH=/usr/lib/jvm/java-21-openjdk/lib/:/usr/lib/jvm/java-21-openjdk/lib/server/
WORKDIR /ghidra

# update and install dependencies used to both build and run ghidra
RUN apk update \
        && apk add openjdk21 python3 \
        bash gcompat \
        fontconfig msttcorefonts-installer \
        linux-headers libressl-dev \
        && update-ms-fonts

FROM base AS build

# install additional dependencies used to build ghidra
RUN apk add gradle \
		python3-dev py-pip \
        alpine-sdk \
        build-base \
        gcc g++ make libc-dev zlib-dev musl-dev \
        zip readline-dev
# copy the contents of the release into the current working dir.
COPY . .

# build postgres and install pyghidra
RUN /ghidra/Ghidra/Features/BSim/support/make-postgres.sh \
        && python3 -m venv /ghidra/venv \
        && /ghidra/venv/bin/python3 -m pip install --no-index -f /ghidra/Ghidra/Features/PyGhidra/pypkg/dist pyghidra \
		&& mkdir /ghidra/repositories && mkdir /ghidra/bsim_datadir


FROM base AS runtime

# install additional dependencies needed for running ghidra
RUN apk add openssl openssh-client \
        xhost musl-locales musl-locales-lang
        
USER ghidra
WORKDIR /ghidra
COPY --chown=ghidra:ghidra --from=build /ghidra /ghidra
