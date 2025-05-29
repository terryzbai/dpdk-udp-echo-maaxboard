DOCKER ?= docker
BASE_IMG ?= debian:sid
USER_IMG := user_img-$(shell whoami)
DOCKER_VOLUME_HOME ?= $(shell whoami)-home

HOST_DIR ?= $(shell pwd)
ROOT_DIR = $(abspath .)
DPDK_DIR = $(ROOT_DIR)/dpdk
# CROSS_FILE = $(ROOT_DIR)/cross-compilation.conf
CROSS_FILE = $(DPDK_DIR)/config/arm/arm64_armv8_linux_gcc
BUILD_DIR = $(ROOT_DIR)/build

DOCKER_BUILD ?= $(DOCKER) build
DOCKER_FLAGS ?= --force-rm=true
ifndef EXEC
	EXEC := bash
	DOCKER_RUN_FLAGS += -it
endif


.PHONY: app
app:
	$(CC) -o test_dpdk_app main.c \
	    $(shell pkg-config --cflags libdpdk) \
	    $(shell pkg-config --libs libdpdk) \
	    -pthread

.PHONY: docker
docker: build_img
	$(DOCKER) run \
		$(DOCKER_RUN_FLAGS) \
		--hostname in-container \
		--rm \
		--group-add sudo \
		-w /host \
		-v $(HOST_DIR):/host:z \
		-v $(DOCKER_VOLUME_HOME):/home/$(shell whoami) \
		-v $(ETC_LOCALTIME):/etc/localtime:ro \
		$(USER_IMG) $(EXEC)

.PHONY: build_img
build_img:
	$(DOCKER_BUILD) $(DOCKER_FLAGS) \
		--build-arg=BASE_IMG=$(BASE_IMG) \
		--build-arg=UNAME=$(shell whoami) \
		--build-arg=UID=$(shell id -u) \
		--build-arg=GID=$(shell id -g) \
		--build-arg=GROUP=$(shell id -gn) \
		-f Dockerfile \
		-t $(USER_IMG) .

clean:
	rm -rf $(BUILD_DIR)
