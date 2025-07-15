// test_enetfec_fixed.c
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_bus_vdev.h>
#include <stdio.h>
#include <signal.h>

/* #define DEBUG_LOG */

#if defined(DEBUG_LOG)
#define LOG_DEBUG(...) do{ printf(__VA_ARGS__); }while(0)
#else
#define LOG_DEBUG(...) do{}while(0)
#endif


#define RX_RING_NUM 1
#define TX_RING_NUM 1
#define RX_RING_SIZE 128
#define TX_RING_SIZE 128

/* #define NUM_MBUFS 8191 */
#define NUM_MBUFS 4000
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define IP_ADDR(a, b, c, d)                           \
    (((uint32_t) a << 24) | ((uint32_t) b << 16) |    \
     ((uint32_t) c << 8) | (uint32_t) d)

#define DPDK_PORT 0
#define SERVER_IP RTE_IPV4(172, 16, 4, 200)
/* #define SERVER_IP RTE_IPV4(10, 0, 2, 15) */
#define SERVER_PORT 1235

/* offload checksum calculations */
static const struct rte_eth_conf port_conf = {
    .rxmode = {
        .mq_mode = RTE_ETH_MQ_RX_NONE,
        .offloads = 0, // Disable all offloads that might use ctrl queue
    },
    .txmode = {
        .mq_mode = RTE_ETH_MQ_TX_NONE,
        .offloads = 0, // Disable all offloads
    },
    .intr_conf = {
        .lsc = 0, // Disable link status change interrupt
        .rxq = 0, // Disable RX queue interrupt
    },
};

static struct rte_mempool *pktmbuf_pool = NULL;
static struct rte_mempool *tx_mbuf_pool = NULL;

void print_dev_info(uint16_t port_id)
{
    struct rte_eth_dev_info dev_info;
    struct rte_ether_addr mac_addr;
    int ret;

    LOG_DEBUG("=== Port %u ===\n", port_id);

    // Get device info safely
    ret = rte_eth_dev_info_get(port_id, &dev_info);
    if (ret == 0) {
        LOG_DEBUG("  Driver: %s\n",
               dev_info.driver_name ? dev_info.driver_name : "Unknown");
        LOG_DEBUG("  Max RX queues: %u\n", dev_info.max_rx_queues);
        LOG_DEBUG("  Max TX queues: %u\n", dev_info.max_tx_queues);
    } else {
        LOG_DEBUG("  Failed to get device info: %d\n", ret);
    }

    // Get MAC address safely
    ret = rte_eth_macaddr_get(port_id, &mac_addr);
    if (ret == 0) {
        LOG_DEBUG("  MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               mac_addr.addr_bytes[0], mac_addr.addr_bytes[1],
               mac_addr.addr_bytes[2], mac_addr.addr_bytes[3],
               mac_addr.addr_bytes[4], mac_addr.addr_bytes[5]);
    } else {
        LOG_DEBUG("  Failed to get MAC address: %d\n", ret);
    }

    // Check if port is valid
    if (rte_eth_dev_is_valid_port(port_id)) {
        LOG_DEBUG("  Port is valid\n");
    } else {
        LOG_DEBUG("  Port is invalid\n");
    }

    /* RX Offload Capabilities */
    LOG_DEBUG("\nRX Offload Capabilities:\n");
    if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_VLAN_STRIP)
        LOG_DEBUG("   VLAN_STRIP\n");
    if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_IPV4_CKSUM)
        LOG_DEBUG("   IPV4_CKSUM\n");
    if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_UDP_CKSUM)
        LOG_DEBUG("   UDP_CKSUM\n");
    if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TCP_CKSUM)
        LOG_DEBUG("   TCP_CKSUM\n");
    if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_SCATTER)
        LOG_DEBUG("   SCATTER\n");
    LOG_DEBUG("========END=======\n");

    /* TX Offload Capabilities */
    LOG_DEBUG("\nTX Offload Capabilities:\n");
    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_VLAN_INSERT)
        LOG_DEBUG("   VLAN_INSERT\n");
    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM)
        LOG_DEBUG("   IPV4_CKSUM\n");
    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_UDP_CKSUM)
        LOG_DEBUG("   UDP_CKSUM\n");
    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_CKSUM)
        LOG_DEBUG("   TCP_CKSUM\n");
    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_TSO)
        LOG_DEBUG("   TCP_TSO\n");
    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MULTI_SEGS)
        LOG_DEBUG("   MULTI_SEGS\n");
    LOG_DEBUG("========END=======\n");
}

static inline int port_init(uint16_t port_id, struct rte_mempool *mbuf_pool)
{
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf *txconf;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    uint16_t q;
    int ret;

    // Enable all multicast so UDP/DHCP/AP work
    /* LOG_DEBUG("Enable allmulticast mode\n"); */
    /* rte_eth_allmulticast_enable(port_id); */

    // Configure ethernet
    LOG_DEBUG("Configure eth device\n");
    ret = rte_eth_dev_configure(port_id, RX_RING_NUM, TX_RING_NUM, &port_conf);
    if (ret != 0) {
        LOG_DEBUG("Failed to configure ethernet device\n");
        return ret;
    }

    // Check that queue descriptors are appropriately sized
    ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd);
    if (ret != 0) {
        LOG_DEBUG("Failed to ajust queue size\n");
        return ret;
    }

    /* Enable TX offloading */
    ret = rte_eth_dev_info_get(0, &dev_info);
    if (ret != 0) {
        LOG_DEBUG("Failed to get dev info\n");
        return -1;
    }
    txconf = &dev_info.default_txconf;

    /* Allocate and set up 1 TX queue per Ethernet port. */
    LOG_DEBUG("Setting up TX queues...\n");
    for (q = 0; q < TX_RING_NUM; q++) {
        ret = rte_eth_tx_queue_setup(port_id, q, nb_txd,
                                     rte_eth_dev_socket_id(port_id), txconf);
        if (ret < 0)
            return ret;
    }

    /* Allocate and set up 1 RX queue per Ethernet port. */
    LOG_DEBUG("Setting up RX queues...\n");
    for (q = 0; q < RX_RING_NUM; q++) {
        ret = rte_eth_rx_queue_setup(port_id, q, nb_rxd,
                                     rte_eth_dev_socket_id(port_id), NULL,
                                     mbuf_pool);
        if (ret < 0)
            return ret;
    }

    /* Set a proper MAC address */
    struct rte_ether_addr mac_addr; // b2:6f:36:15:cd:60
    mac_addr.addr_bytes[0] = 0xb2;  /* Locally administered */
    mac_addr.addr_bytes[1] = 0x6f;
    mac_addr.addr_bytes[2] = 0x36;
    mac_addr.addr_bytes[3] = 0x15;
    mac_addr.addr_bytes[4] = 0xcd;
    mac_addr.addr_bytes[5] = 0x60;

    ret= rte_eth_dev_default_mac_addr_set(0, &mac_addr);
    if (ret!= 0) {
        LOG_DEBUG("Warning: Could not set MAC address: %s\n", strerror(-ret));
    }

    /* Start the Ethernet port. */
    LOG_DEBUG("Start the eth dev.\n");
    ret = rte_eth_dev_start(port_id);
    if (ret < 0) {
        LOG_DEBUG("Failed to start ethernet device\n");
        return ret;
    }

    /* Enable RX in promiscuous mode for the Ethernet device. */
    /* rte_eth_promiscuous_enable(port_id); */

    return 0;
}

/* Convert IP address to string */
static void be_ip_to_str(uint32_t ip, char *str)
{
    sprintf(str, "%d.%d.%d.%d",
            ip & 0xFF, (ip >> 8) & 0xFF,
            (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
}

static void handle_arp_packet(struct rte_mbuf *rx_mbuf, uint16_t port_id)
{
    // Clone the received mbuf
    struct rte_mbuf *tx_mbuf = rte_pktmbuf_clone(rx_mbuf, tx_mbuf_pool);
    if (tx_mbuf == NULL) {
        LOG_DEBUG("Failed to clone mbuf\n");
    }

    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(tx_mbuf, struct rte_ether_hdr *);
    struct rte_arp_hdr *arp_hdr = (struct rte_arp_hdr *)(eth_hdr + 1);

    struct rte_ether_addr src_mac;
    struct rte_ether_addr dst_mac;
    rte_eth_macaddr_get(port_id, &src_mac);
    /* rte_ether_addr_copy(&arp_hdr->arp_data.arp_tha, &src_mac); */
    rte_ether_addr_copy(&arp_hdr->arp_data.arp_sha, &dst_mac);

    LOG_DEBUG("=========\n");
    LOG_DEBUG("  SRC MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
       src_mac.addr_bytes[0], src_mac.addr_bytes[1],
       src_mac.addr_bytes[2], src_mac.addr_bytes[3],
       src_mac.addr_bytes[4], src_mac.addr_bytes[5]);

    LOG_DEBUG("  DST MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
       dst_mac.addr_bytes[0], dst_mac.addr_bytes[1],
       dst_mac.addr_bytes[2], dst_mac.addr_bytes[3],
       dst_mac.addr_bytes[4], dst_mac.addr_bytes[5]);

    uint32_t src_ip = arp_hdr->arp_data.arp_tip;
    uint32_t dst_ip = arp_hdr->arp_data.arp_sip;
    char src_ip_str[16];
    char dst_ip_str[16];
    be_ip_to_str(src_ip, src_ip_str);
    be_ip_to_str(dst_ip, dst_ip_str);

    LOG_DEBUG("  SRC IP: %s\n", dst_ip_str);
    LOG_DEBUG("  DST IP: %s\n", src_ip_str);
    LOG_DEBUG("  ARP IP: 0x%x\n", src_ip);
    LOG_DEBUG("  SERVER: 0x%x\n", rte_cpu_to_be_32(SERVER_IP));

    if (rte_be_to_cpu_16(arp_hdr->arp_opcode) == RTE_ARP_OP_REQUEST) {
        rte_ether_addr_copy(&dst_mac, &eth_hdr->dst_addr);
        rte_ether_addr_copy(&src_mac, &eth_hdr->src_addr);

        arp_hdr->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);

        // ARP data
        rte_ether_addr_copy(&src_mac, &arp_hdr->arp_data.arp_sha);
        arp_hdr->arp_data.arp_sip = src_ip;
        rte_ether_addr_copy(&dst_mac, &arp_hdr->arp_data.arp_tha);
        arp_hdr->arp_data.arp_tip = dst_ip;

        rte_eth_tx_burst(port_id, 0, &tx_mbuf, 1);
        LOG_DEBUG("ARP ACK from src %s to dst %s\n", src_ip_str, dst_ip_str);
        LOG_DEBUG("------------------\n");
    }
    LOG_DEBUG("=========\n");
}

static void
print_udp_info(struct rte_ipv4_hdr *ipv4_hdr, struct rte_udp_hdr *udp_hdr,
               const uint8_t *data, uint16_t data_len, const char *direction)
{
    LOG_DEBUG("[%s] %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d (%d bytes): ",
           direction,
           (rte_be_to_cpu_32(ipv4_hdr->src_addr) >> 24) & 0xFF,
           (rte_be_to_cpu_32(ipv4_hdr->src_addr) >> 16) & 0xFF,
           (rte_be_to_cpu_32(ipv4_hdr->src_addr) >> 8) & 0xFF,
           (rte_be_to_cpu_32(ipv4_hdr->src_addr) >> 0) & 0xFF,
           rte_be_to_cpu_16(udp_hdr->src_port),
           (rte_be_to_cpu_32(ipv4_hdr->dst_addr) >> 24) & 0xFF,
           (rte_be_to_cpu_32(ipv4_hdr->dst_addr) >> 16) & 0xFF,
           (rte_be_to_cpu_32(ipv4_hdr->dst_addr) >> 8) & 0xFF,
           (rte_be_to_cpu_32(ipv4_hdr->dst_addr) >> 0) & 0xFF,
           rte_be_to_cpu_16(udp_hdr->dst_port),
           data_len);

    // Print data as string if printable
    bool printable = true;
    for (int i = 0; i < data_len; i++) {
        if (!isprint(data[i]) && data[i] != '\n' && data[i] != '\r' && data[i] != '\t') {
            printable = false;
            break;
        }
    }

    if (printable && data_len > 0) {
        LOG_DEBUG("\"");
        for (int i = 0; i < data_len; i++) {
            if (data[i] == '\n') LOG_DEBUG("\\n");
            else if (data[i] == '\r') LOG_DEBUG("\\r");
            else if (data[i] == '\t') LOG_DEBUG("\\t");
            else LOG_DEBUG("%c", data[i]);
        }
        LOG_DEBUG("\"\n");
    } else {
        LOG_DEBUG("[");
        for (int i = 0; i < data_len && i < 32; i++) {
            LOG_DEBUG("%02x%s", data[i], (i < data_len - 1) ? " " : "");
        }
        if (data_len > 32) LOG_DEBUG("...");
        LOG_DEBUG("]\n");
    }
}

static void echo_udp_packet(struct rte_mbuf *rx_mbuf, uint16_t port_id)
{
    // Clone the received mbuf
    struct rte_mbuf *tx_mbuf = rte_pktmbuf_clone(rx_mbuf, tx_mbuf_pool);
    if (tx_mbuf == NULL) {
        LOG_DEBUG("Failed to clone mbuf\n");
    }

    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(tx_mbuf, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)((char *)eth_hdr + sizeof(struct rte_ether_hdr));
    struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)((char *)ipv4_hdr + (ipv4_hdr->version_ihl & 0x0F) * 4);

    // Get UDP data
    uint8_t *udp_data = (uint8_t *)udp_hdr + sizeof(struct rte_udp_hdr);
    uint16_t udp_data_len = rte_be_to_cpu_16(udp_hdr->dgram_len) - sizeof(struct rte_udp_hdr);

    // Print received packet info
    print_udp_info(ipv4_hdr, udp_hdr, udp_data, udp_data_len, "RX");

    // Swap Ethernet addresses
    struct rte_ether_addr tmp_eth;
    rte_ether_addr_copy(&eth_hdr->dst_addr, &tmp_eth);
    rte_ether_addr_copy(&eth_hdr->src_addr, &eth_hdr->dst_addr);
    rte_ether_addr_copy(&tmp_eth, &eth_hdr->src_addr);

    // Swap IP addresses
    uint32_t tmp_ip = ipv4_hdr->src_addr;
    ipv4_hdr->src_addr = ipv4_hdr->dst_addr;
    ipv4_hdr->dst_addr = tmp_ip;

    // Swap UDP ports
    uint16_t tmp_port = udp_hdr->src_port;
    udp_hdr->src_port = udp_hdr->dst_port;
    udp_hdr->dst_port = tmp_port;

    // Recalculate checksums
    ipv4_hdr->hdr_checksum = 0;
    ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);

    udp_hdr->dgram_cksum = 0;
    udp_hdr->dgram_cksum = rte_ipv4_udptcp_cksum(ipv4_hdr, udp_hdr);

    // Print echo packet info
    print_udp_info(ipv4_hdr, udp_hdr, udp_data, udp_data_len, "TX");

    // Send the packet back
    uint16_t nb_tx = rte_eth_tx_burst(port_id, 0, &tx_mbuf, 1);
    if (nb_tx == 0) {
        LOG_DEBUG("Failed to send echo packet\n");
        rte_pktmbuf_free(tx_mbuf);
    }
}

static void handle_udp_packet(struct rte_mbuf *mbuf, uint16_t port_id)
{
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)((char *)eth_hdr + sizeof(struct rte_ether_hdr));
    struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)((char *)ipv4_hdr + (ipv4_hdr->version_ihl & 0x0F) * 4);

    // Calculate UDP data pointer and length
    uint8_t *udp_data = (uint8_t *)udp_hdr + sizeof(struct rte_udp_hdr);
    uint16_t udp_data_len = rte_be_to_cpu_16(udp_hdr->dgram_len) - sizeof(struct rte_udp_hdr);

    // Print UDP data
    LOG_DEBUG("len: %d, addr: %u, port: %u\n", udp_data_len, ipv4_hdr->dst_addr, udp_hdr->dst_port);
    if (udp_data_len > 0 && ipv4_hdr->dst_addr == rte_cpu_to_be_32(SERVER_IP) && udp_hdr->dst_port == rte_cpu_to_be_16(SERVER_PORT)) {
        echo_udp_packet(mbuf, port_id);
    } else {
        LOG_DEBUG("No UDP data\n");
    }
    LOG_DEBUG("===========================\n");
}


static inline void dcache_invalidate_range(void *addr, size_t size) {
    uintptr_t start = (uintptr_t)addr;
    uintptr_t end = start + size;
    uintptr_t cache_line_size = 64; // ARM64 cache line size

    // Align to cache line boundaries
    start &= ~(cache_line_size - 1);
    LOG_DEBUG("Invalidate cache: 0x%x - 0x%x\n", start, end);

    for (uintptr_t va = start; va < end; va += cache_line_size) {
        asm volatile("dc civac, %0" : : "r" (va) );
    }

    // Data synchronization barrier
    asm volatile("dsb sy" : : : "memory");
    /* asm volatile("dmb sy" : : : "memory"); */
}

static inline void dcache_clean_range(void *addr, size_t size) {
    uintptr_t start = (uintptr_t)addr;
    uintptr_t end = start + size;
    uintptr_t cache_line_size = 64;

    start &= ~(cache_line_size - 1);
    LOG_DEBUG("Clean cache: 0x%x - 0x%x\n", start, end);

    for (uintptr_t va = start; va < end; va += cache_line_size) {
        asm volatile("dc cvac, %0" : : "r" (va) : "memory");
    }

    asm volatile("dsb sy" : : : "memory");
    /* asm volatile("dmb sy" : : : "memory"); */
}

void run_udp_echoserver(uint16_t port_id)
{
    struct rte_mbuf *bufs[BURST_SIZE];
    uint16_t nb_rx, i;

    LOG_DEBUG("UDP Echoserver running...\n");

    // Check link status
    struct rte_eth_link link;
    int ret = rte_eth_link_get_nowait(port_id, &link);
    if (ret == 0) {
        LOG_DEBUG("Link: %s, Speed: %u\n",
               link.link_status ? "UP" : "DOWN", link.link_speed);
    }

    while (true) {
        /* receive packets */
        nb_rx = rte_eth_rx_burst(port_id, 0, bufs, BURST_SIZE);

        if (nb_rx == 0) // If no packets were received, continue to the next iteration
            continue;

        /* Process each packet */
        for (i = 0; i < nb_rx; i++) {
            void *pkt_data = rte_pktmbuf_mtod(bufs[i], void *);
            uint16_t data_len = rte_pktmbuf_data_len(bufs[i]);

            // Invalidate cache before reading DMA data
            dcache_invalidate_range(pkt_data, data_len);

            struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr *);
            uint16_t ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);

            LOG_DEBUG("Packet (1/%d) - type 0x%x \n", nb_rx, ether_type);
            if (ether_type == RTE_ETHER_TYPE_ARP) {
                struct rte_arp_hdr *arp_hdr = (struct rte_arp_hdr *)(eth_hdr + 1);
                char test_src_ip_str[16];
                char test_dst_ip_str[16];
                be_ip_to_str(arp_hdr->arp_data.arp_sip, test_src_ip_str);
                be_ip_to_str(arp_hdr->arp_data.arp_tip, test_dst_ip_str);
                LOG_DEBUG("ARP: 0x%x - 0x%x, ip from %s to %s\n", arp_hdr->arp_data.arp_tip, rte_cpu_to_be_32(SERVER_IP), test_src_ip_str, test_dst_ip_str);
                if (arp_hdr->arp_data.arp_tip == rte_cpu_to_be_32(SERVER_IP)) {
                    handle_arp_packet(bufs[i], port_id);
                }
            } else if (ether_type == RTE_ETHER_TYPE_IPV4) {
                struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);

                if (ip_hdr->next_proto_id == IPPROTO_UDP) {
                    handle_udp_packet(bufs[i], port_id);
                }
            }

            rte_pktmbuf_free(bufs[i]);
        }
    }
}

int main(int argc, char *argv[])
{
    int ret;
    uint16_t nb_ports;
    uint16_t port_id;

    LOG_DEBUG("Initializing DPDK EAL...\n");
    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        LOG_DEBUG("EAL initialization failed: %d\n", ret);
        return -1;
    }

    LOG_DEBUG("EAL initialized successfully\n");

    nb_ports = rte_eth_dev_count_avail();

    if (nb_ports == 0) {
        LOG_DEBUG("No Ethernet ports found!\n");
        LOG_DEBUG("Make sure to use: --vdev='net_enetfec'\n");
        return -1;
    } else {
        LOG_DEBUG("Available Ethernet ports: %u\n", nb_ports);
    }

    ret = rte_eth_dev_is_valid_port(DPDK_PORT);
    if (ret == 0) {
        LOG_DEBUG("The target port %u is not valid\n", DPDK_PORT);
        return -1;
    }
    LOG_DEBUG("Port %d is valid.\n", DPDK_PORT);

    // Allocate rx mempool
    LOG_DEBUG("Creating mbuf_pool for RX...\n");
    assert((pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_rx_pool",
                                                   NUM_MBUFS,
                                                   MBUF_CACHE_SIZE,
                                                   0,
                                                   RTE_MBUF_DEFAULT_BUF_SIZE,
                                                   rte_socket_id())) != NULL);
    if (pktmbuf_pool == NULL) {
        LOG_DEBUG("Failed to create mbufpool\n");
        return -1;
    }

    // Allocate tx mempool
    LOG_DEBUG("Creating mbuf_pool for TX...\n");
    assert((tx_mbuf_pool = rte_pktmbuf_pool_create("mbuf_tx_pool",
                                                   NUM_MBUFS,
                                                   MBUF_CACHE_SIZE,
                                                   0,
                                                   RTE_MBUF_DEFAULT_BUF_SIZE,
                                                   rte_socket_id())) != NULL);
    if (pktmbuf_pool == NULL) {
        LOG_DEBUG("Failed to create mbufpool\n");
        return -1;
    }


    LOG_DEBUG("Initialising the port %d\n", DPDK_PORT);
    ret = port_init(DPDK_PORT, pktmbuf_pool);
    if (ret != 0) {
        LOG_DEBUG("Faield to init port %u\n", DPDK_PORT);
        return -1;
    }
    LOG_DEBUG("Network device initialisation successful!\n");

    print_dev_info(DPDK_PORT);
    run_udp_echoserver(DPDK_PORT);
    /* run_udp_sender(DPDK_PORT); */

    LOG_DEBUG("Stopping port %u...\n", DPDK_PORT);
    ret = rte_eth_dev_stop(DPDK_PORT);
    if (ret != 0) {
        LOG_DEBUG("Failed to stop port %u: %s\n", DPDK_PORT, strerror(-ret));
    } else {
        LOG_DEBUG("Port %u stopped successfully\n", DPDK_PORT);
    }

    LOG_DEBUG("Closing port %u...\n", DPDK_PORT);
    ret = rte_eth_dev_close(DPDK_PORT);
    if (ret != 0) {
        LOG_DEBUG("Failed to close port %u: %d\n", DPDK_PORT, ret);
    }

    // Final cleanup
    ret = rte_eal_cleanup();
    if (ret != 0) {
        LOG_DEBUG("EAL cleanup failed: %d\n", ret);
    } else {
        LOG_DEBUG("EAL cleanup successful\n");
    }

    return 0;
}
