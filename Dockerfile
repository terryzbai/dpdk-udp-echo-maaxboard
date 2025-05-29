ARG BASE_IMG=extras
FROM $BASE_IMG

# Get user UID and username
ARG UID
ARG UNAME
ARG GID
ARG GROUP

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV CC=aarch64-linux-gnu-gcc
ENV CXX=aarch64-linux-gnu-g++
ENV AR=aarch64-linux-gnu-gcc-ar
ENV STRIP=aarch64-linux-gnu-strip

# Install base packages and cross-compilation toolchain
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc-aarch64-linux-gnu \
    g++-aarch64-linux-gnu \
    pkg-config \
    libdpdk-dev \
    cmake \
    && rm -rf /var/lib/apt/lists/*

# Install meson build system
# RUN pip3 install meson pyelftools

RUN /bin/bash

VOLUME /home/${UNAME}
