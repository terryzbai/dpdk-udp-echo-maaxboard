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
DPDK_BUILD_DIR = $(ROOT_DIR)/dpdk/build
DPDK_BUILD_DIR = $(ROOT_DIR)/libdpdk

DOCKER_BUILD ?= $(DOCKER) build
DOCKER_FLAGS ?= --force-rm=true
ifndef EXEC
	EXEC := bash
	DOCKER_RUN_FLAGS += -it
endif


.PHONY: app
app:
	$(CC) -o test_dpdk_app test_dpdk_app.c \
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

.PHONY: build_dpdk
build_dpdk:
	cd $(HOST_DIR)/dpdk && \
	PKG_CONFIG_LIBDIR=/usr/lib/aarch64-linux-gnu/pkgconfig \
	meson setup $(DPDK_BUILD_DIR) \
		--cross-file config/arm/arm64_armv8_linux_gcc \
		--prefix=/usr \
	    --libdir=lib \
	    --buildtype=release \
	    --default-library=shared \
	    -Dplatform=generic \
	    -Denable_kmods=false \
	    -Dtests=false \
	    -Dexamples= \
	    -Denable_docs=false \
	    -Ddisable_libs=acl,bbdev,bitratestats,bpf,cfgfile,cmdline,compressdev,cryptodev,distributor,efd,fib,flow_classify,graph,gro,gso,hash,ip_frag,jobstats,kni,latencystats,lpm,member,meter,metrics,power,rawdev,regexdev,reorder,sched,security,table,timer \
	    -Ddisable_drivers=baseband,compress,crypto,event,net/af_packet,net/af_xdp,net/ark,net/atlantic,net/avp,net/axgbe,net/bnx2x,net/bnxt,net/bond,net/cxgbe,net/dpaa,net/dpaa2,net/e1000,net/ena,net/enetc,net/enic,net/failsafe,net/fm10k,net/hinic,net/hns3,net/i40e,net/iavf,net/ice,net/igc,net/ionic,net/ixgbe,net/kni,net/liquidio,net/memif,net/mlx4,net/mlx5,net/netvsc,net/nfp,net/null,net/octeontx,net/octeontx2,net/pcap,net/pfe,net/qede,net/ring,net/sfc,net/softnic,net/tap,net/thunderx,net/txgbe,net/vdev_netvsc,net/vhost,net/vmxnet3,raw,regex,vdpa \
	    -Denable_drivers=net/virtio,net/enetfec && \
	ninja -C $(DPDK_BUILD_DIR) && \
	ninja install -C $(DPDK_BUILD_DIR) && \
	mkdir -p /host/libdpdk && \
	cp -P /usr/lib/librte* /host/libdpdk && \
	cp -rP /usr/lib/dpdk /host/libdpdk && \
	export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/host/libdpdk/pkgconfig


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

CFLAGS = -O0
CFLAGS += -Wall -Wunused-function
CFLAGS += -Wextra -I. -Iinclude
LDFLAGS += -lpthread -lm

CFLAGS += $(shell pkg-config --cflags libdpdk)
LDFLAGS += $(shell pkg-config --libs libdpdk)
C_SRCS = main.c udpecho.c
C_OBJS = $(C_SRCS:.c=.o)

LWIP_SRC_DIR = $(ROOT_DIR)/lwip
CONTRIB_SRC_DIR = $(ROOT_DIR)/lwip-contrib
CFLAGS += -I$(LWIP_SRC_DIR)/src/include -I$(CONTRIB_SRC_DIR) -I$(CONTRIB_SRC_DIR)/ports/unix/port/include
LWIP_OBJS = $(LWIP_SRC_DIR)/src/api/api_lib.o \
			$(LWIP_SRC_DIR)/src/api/api_msg.o \
			$(LWIP_SRC_DIR)/src/api/err.o \
			$(LWIP_SRC_DIR)/src/api/if_api.o \
			$(LWIP_SRC_DIR)/src/api/netbuf.o \
			$(LWIP_SRC_DIR)/src/api/netdb.o \
			$(LWIP_SRC_DIR)/src/api/netifapi.o \
			$(LWIP_SRC_DIR)/src/api/sockets.o \
			$(LWIP_SRC_DIR)/src/api/tcpip.o \
			$(LWIP_SRC_DIR)/src/core/altcp_alloc.o \
			$(LWIP_SRC_DIR)/src/core/altcp.o \
			$(LWIP_SRC_DIR)/src/core/altcp_tcp.o \
			$(LWIP_SRC_DIR)/src/core/def.o \
			$(LWIP_SRC_DIR)/src/core/dns.o \
			$(LWIP_SRC_DIR)/src/core/inet_chksum.o \
			$(LWIP_SRC_DIR)/src/core/init.o \
			$(LWIP_SRC_DIR)/src/core/ip.o \
			$(LWIP_SRC_DIR)/src/core/ipv4/autoip.o \
			$(LWIP_SRC_DIR)/src/core/ipv4/dhcp.o \
			$(LWIP_SRC_DIR)/src/core/ipv4/etharp.o \
			$(LWIP_SRC_DIR)/src/core/ipv4/icmp.o \
			$(LWIP_SRC_DIR)/src/core/ipv4/igmp.o \
			$(LWIP_SRC_DIR)/src/core/ipv4/ip4_addr.o \
			$(LWIP_SRC_DIR)/src/core/ipv4/ip4.o \
			$(LWIP_SRC_DIR)/src/core/ipv4/ip4_frag.o \
			$(LWIP_SRC_DIR)/src/core/ipv6/dhcp6.o \
			$(LWIP_SRC_DIR)/src/core/ipv6/ethip6.o \
			$(LWIP_SRC_DIR)/src/core/ipv6/icmp6.o \
			$(LWIP_SRC_DIR)/src/core/ipv6/inet6.o \
			$(LWIP_SRC_DIR)/src/core/ipv6/ip6_addr.o \
			$(LWIP_SRC_DIR)/src/core/ipv6/ip6.o \
			$(LWIP_SRC_DIR)/src/core/ipv6/ip6_frag.o \
			$(LWIP_SRC_DIR)/src/core/ipv6/mld6.o  \
			$(LWIP_SRC_DIR)/src/core/ipv6/nd6.o   \
			$(LWIP_SRC_DIR)/src/core/mem.o \
			$(LWIP_SRC_DIR)/src/core/memp.o \
			$(LWIP_SRC_DIR)/src/core/netif.o \
			$(LWIP_SRC_DIR)/src/core/pbuf.o \
			$(LWIP_SRC_DIR)/src/core/raw.o \
			$(LWIP_SRC_DIR)/src/core/stats.o \
			$(LWIP_SRC_DIR)/src/core/sys.o \
			$(LWIP_SRC_DIR)/src/core/tcp.o \
			$(LWIP_SRC_DIR)/src/core/tcp_in.o \
			$(LWIP_SRC_DIR)/src/core/tcp_out.o \
			$(LWIP_SRC_DIR)/src/core/timeouts.o \
			$(LWIP_SRC_DIR)/src/core/udp.o \
			$(LWIP_SRC_DIR)/src/netif/ethernet.o \
			$(LWIP_SRC_DIR)/src/netif/ppp/ppp.o \
			$(LWIP_SRC_DIR)/src/netif/ppp/pppoe.o \
			$(LWIP_SRC_DIR)/src/netif/ppp/auth.o \
			$(LWIP_SRC_DIR)/src/netif/ppp/ccp.o \
			$(LWIP_SRC_DIR)/src/netif/ppp/chap_ms.o \
			$(LWIP_SRC_DIR)/src/netif/ppp/demand.o \
			$(LWIP_SRC_DIR)/src/netif/ppp/eap.o \
			$(LWIP_SRC_DIR)/src/netif/ppp/ecp.o \
			$(LWIP_SRC_DIR)/src/netif/ppp/fsm.o \
			$(LWIP_SRC_DIR)/src/netif/ppp/lcp.o \
			$(LWIP_SRC_DIR)/src/netif/ppp/pppapi.o \
			$(LWIP_SRC_DIR)/src/netif/ppp/utils.o \
			$(LWIP_SRC_DIR)/src/netif/ppp/mppe.o \
			$(CONTRIB_SRC_DIR)/ports/unix/port/sys_arch.o

OBJS = $(C_OBJS) $(LWIP_OBJS)
$(OBJS): $(CONTRIB_SRC_DIR) $(LWIP_SRC_DIR)

.PHONY: udp_echo
udp_echo: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean_udp_echo:
	rm -rf $(OBJS)


clean:
	rm -rf $(BUILD_DIR)
	rm -rf $(DPDK_BUILD_DIR)
	rm -rf $(DPDK_LIB)
