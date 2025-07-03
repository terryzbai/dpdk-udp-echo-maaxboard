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
    python3 \
    python3-pip \
    pkg-config \
    cmake \
    ninja-build \
    meson \
    linux-headers-generic \
    pciutils \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Install meson build system
RUN pip3 install pyelftools --break-system-packages

RUN /bin/bash

VOLUME /home/${UNAME}
