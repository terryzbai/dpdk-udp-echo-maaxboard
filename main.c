// test_enetfec_fixed.c
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_bus_vdev.h>
#include <stdio.h>
#include <signal.h>

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
#define CLIENT_IP IP_ADDR(172, 16, 1, 100)
#define CLIENT_PORT 1235
#define SERVER_IP IP_ADDR(255, 255, 255, 255)
#define SERVER_PORT 1235
#define PAYLOAD_LEN 22

/* offload checksum calculations */
static const struct rte_eth_conf port_conf = {
    .rxmode = {
        .offloads = 0,
    },
    .txmode = {
        .offloads = 0,
    },
};

/* Server configuration */
struct server_config {
    uint32_t server_ip;     /* Server IP in network byte order */
    struct rte_ether_addr server_mac;
    struct rte_ether_addr client_mac;  /* Will be learned from first packet */
    uint16_t udp_port;
    bool client_learned;
};

static struct server_config config = {
    .server_ip = RTE_IPV4(172, 16, 1, 100),  /* Default server IP */
    .udp_port = SERVER_PORT,
    .client_learned = false
};

static struct rte_mempool *pktmbuf_pool = NULL;
static struct rte_mempool *tx_mbuf_pool = NULL;

void print_dev_info(uint16_t port_id)
{
    struct rte_eth_dev_info dev_info;
    struct rte_ether_addr mac_addr;
    int ret;

    printf("=== Port %u ===\n", port_id);

    // Get device info safely
    ret = rte_eth_dev_info_get(port_id, &dev_info);
    if (ret == 0) {
        printf("  Driver: %s\n",
               dev_info.driver_name ? dev_info.driver_name : "Unknown");
        printf("  Max RX queues: %u\n", dev_info.max_rx_queues);
        printf("  Max TX queues: %u\n", dev_info.max_tx_queues);
    } else {
        printf("  Failed to get device info: %d\n", ret);
    }

    // Get MAC address safely
    ret = rte_eth_macaddr_get(port_id, &mac_addr);
    if (ret == 0) {
        printf("  MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               mac_addr.addr_bytes[0], mac_addr.addr_bytes[1],
               mac_addr.addr_bytes[2], mac_addr.addr_bytes[3],
               mac_addr.addr_bytes[4], mac_addr.addr_bytes[5]);
    } else {
        printf("  Failed to get MAC address: %d\n", ret);
    }

    // Check if port is valid
    if (rte_eth_dev_is_valid_port(port_id)) {
        printf("  Port is valid\n");
    } else {
        printf("  Port is invalid\n");
    }

    /* RX Offload Capabilities */
    printf("\nRX Offload Capabilities:\n");
    if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_VLAN_STRIP)
        printf("   VLAN_STRIP\n");
    if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_IPV4_CKSUM)
        printf("   IPV4_CKSUM\n");
    if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_UDP_CKSUM)
        printf("   UDP_CKSUM\n");
    if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_TCP_CKSUM)
        printf("   TCP_CKSUM\n");
    if (dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_SCATTER)
        printf("   SCATTER\n");
    printf("========END=======\n");

    /* TX Offload Capabilities */
    printf("\nTX Offload Capabilities:\n");
    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_VLAN_INSERT)
        printf("   VLAN_INSERT\n");
    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM)
        printf("   IPV4_CKSUM\n");
    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_UDP_CKSUM)
        printf("   UDP_CKSUM\n");
    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_CKSUM)
        printf("   TCP_CKSUM\n");
    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_TSO)
        printf("   TCP_TSO\n");
    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MULTI_SEGS)
        printf("   MULTI_SEGS\n");
    printf("========END=======\n");
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
    rte_eth_allmulticast_enable(port_id);

    // Configure ethernet
    ret = rte_eth_dev_configure(port_id, RX_RING_NUM, TX_RING_NUM, &port_conf);
    if (ret != 0) {
        printf("Failed to configure ethernet device\n");
        return ret;
    }

    // Check that queue descriptors are appropriately sized
    ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd);
    if (ret != 0) {
        printf("Failed to ajust queue size\n");
        return ret;
    }

    /* Allocate and set up 1 RX queue per Ethernet port. */
    for (q = 0; q < RX_RING_NUM; q++) {
        ret = rte_eth_rx_queue_setup(port_id, q, nb_rxd,
                                     rte_eth_dev_socket_id(port_id), NULL,
                                     mbuf_pool);
        if (ret < 0)
            return ret;
    }

    /* Enable TX offloading */
    ret = rte_eth_dev_info_get(0, &dev_info);
    if (ret != 0) {
        printf("Failed to get dev info\n");
        return -1;
    }
    txconf = &dev_info.default_txconf;

    /* Allocate and set up 1 TX queue per Ethernet port. */
    for (q = 0; q < TX_RING_NUM; q++) {
        ret = rte_eth_tx_queue_setup(port_id, q, nb_txd,
                                     rte_eth_dev_socket_id(port_id), txconf);
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
        printf("Warning: Could not set MAC address: %s\n", strerror(-ret));
    }

    /* Start the Ethernet port. */
    ret = rte_eth_dev_start(port_id);
    if (ret < 0) {
        printf("Failed to start ethernet device\n");
        return ret;
    }

    /* Enable RX in promiscuous mode for the Ethernet device. */
    rte_eth_promiscuous_enable(port_id);

    return 0;
}

/* Convert IP address to string */
static void ip_to_str(uint32_t ip, char *str)
{
    sprintf(str, "%d.%d.%d.%d",
            (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
            (ip >> 8) & 0xFF, ip & 0xFF);
}

static void handle_arp_packet(struct rte_mbuf *mbuf, uint16_t port_id)
{
    struct rte_ether_hdr *eth_hdr;
    struct rte_arp_hdr *arp_hdr;

    char ip_str[16];

    eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    arp_hdr = (struct rte_arp_hdr *)(eth_hdr + 1);

    ip_to_str(arp_hdr->arp_data.arp_tip, ip_str);
    printf("Received ARP request for IP: %s\n", ip_str);
    /* Check if it's an ARP request for our IP */
    if (rte_be_to_cpu_16(arp_hdr->arp_opcode) == RTE_ARP_OP_REQUEST &&
        arp_hdr->arp_data.arp_tip == config.server_ip) {

        printf("Received ARP request for our IP, sending reply\n");
    }
}

static void handle_udp_packet(struct rte_mbuf *mbuf, uint16_t port_id)
{

}

void run_udp_sender(uint16_t port_id)
{
    uint64_t start_time, end_time;
    struct rte_mbuf *bufs[BURST_SIZE];
    struct rte_mbuf *buf;
    struct rte_ether_hdr *ptr_mac_hdr;
    char *buf_ptr;
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ipv4_hdr;
    struct rte_udp_hdr *rte_udp_hdr;
    uint32_t nb_tx, nb_rx, i;
    uint64_t reqs = 0;
    struct rte_ether_addr server_eth;
    char mac_buf[64];
    uint64_t time_received;
    int ret;

    buf = rte_pktmbuf_alloc(tx_mbuf_pool);
    if (buf == NULL)
        printf("error allocating tx mbuf\n");

    /* ethernet header */
    buf_ptr = rte_pktmbuf_append(buf, RTE_ETHER_HDR_LEN);
    eth_hdr = (struct rte_ether_hdr *) buf_ptr;

    struct rte_ether_addr mac_addr;
    ret = rte_eth_macaddr_get(port_id, &mac_addr);
    if (ret) {
        printf("Failed to get mac address\n");
    }
    rte_ether_addr_copy(&mac_addr, &eth_hdr->src_addr);

    /* Set a proper MAC address */
    struct rte_ether_addr server_mac_addr;
    mac_addr.addr_bytes[0] = 0xff;
    mac_addr.addr_bytes[1] = 0xff;
    mac_addr.addr_bytes[2] = 0xff;
    mac_addr.addr_bytes[3] = 0xff;
    mac_addr.addr_bytes[4] = 0xff;
    mac_addr.addr_bytes[5] = 0xff;
    rte_ether_addr_copy(&server_mac_addr, &eth_hdr->dst_addr);

    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    /* IPv4 header */
    buf_ptr = rte_pktmbuf_append(buf, sizeof(struct rte_ipv4_hdr));
    ipv4_hdr = (struct rte_ipv4_hdr *) buf_ptr;
    ipv4_hdr->version_ihl = 0x45;
    ipv4_hdr->type_of_service = 0;
    ipv4_hdr->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) +
            sizeof(struct rte_udp_hdr) + PAYLOAD_LEN);
    ipv4_hdr->packet_id = 0;
    ipv4_hdr->fragment_offset = 0;
    ipv4_hdr->time_to_live = 64;
    ipv4_hdr->next_proto_id = IPPROTO_UDP;
    ipv4_hdr->hdr_checksum = 0;
    ipv4_hdr->src_addr = rte_cpu_to_be_32(CLIENT_IP);
    ipv4_hdr->dst_addr = rte_cpu_to_be_32(SERVER_IP);

    /* UDP header + fake data */
    buf_ptr = rte_pktmbuf_append(buf,
            sizeof(struct rte_udp_hdr) + PAYLOAD_LEN);
    rte_udp_hdr = (struct rte_udp_hdr *) buf_ptr;
    rte_udp_hdr->src_port = rte_cpu_to_be_16(CLIENT_PORT);
    rte_udp_hdr->dst_port = rte_cpu_to_be_16(SERVER_PORT);
    rte_udp_hdr->dgram_len = rte_cpu_to_be_16(sizeof(struct rte_udp_hdr)
            + PAYLOAD_LEN);
    rte_udp_hdr->dgram_cksum = 0;
    memset(buf_ptr + sizeof(struct rte_udp_hdr), 0xAB, PAYLOAD_LEN);

    buf->l2_len = RTE_ETHER_HDR_LEN;
    buf->l3_len = sizeof(struct rte_ipv4_hdr);
    buf->ol_flags = RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4;

    /* send packet */
    nb_tx = rte_eth_tx_burst(port_id, 0, &buf, 1);
    printf("Sent a packet\n");

    if (unlikely(nb_tx != 1)) {
        printf("error: could not send packet\n");
    }
}

void run_udp_echoserver(uint16_t port_id)
{
    struct rte_mbuf *bufs[BURST_SIZE];
    uint16_t nb_rx, i;

    printf("UDP Echoserver running...\n");

    // Check link status
    struct rte_eth_link link;
    int ret = rte_eth_link_get_nowait(port_id, &link);
    if (ret == 0) {
        printf("Link: %s, Speed: %u\n",
               link.link_status ? "UP" : "DOWN", link.link_speed);
    }

    while (true) {
        /* receive packets */
        nb_rx = rte_eth_rx_burst(port_id, 0, bufs, BURST_SIZE);

        if (nb_rx == 0) // If no packets were received, continue to the next iteration
            continue;

        printf("received a packet!\n");

        /* Process each packet */
        for (i = 0; i < nb_rx; i++) {
            struct rte_ether_hdr *eth_hdr;
            uint16_t ether_type;

            eth_hdr = rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr *);
            ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);

            if (ether_type == RTE_ETHER_TYPE_ARP) {
                handle_arp_packet(bufs[i], port_id);
            } else if (ether_type == RTE_ETHER_TYPE_IPV4) {
                struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);

                if (ip_hdr->next_proto_id == IPPROTO_UDP) {
                    handle_udp_packet(bufs[i], port_id);
                } else {
                    rte_pktmbuf_free(bufs[i]);
                }
            } else {
                rte_pktmbuf_free(bufs[i]);
            }
        }

    }
}

int main(int argc, char *argv[])
{
    int ret;
    uint16_t nb_ports;
    uint16_t port_id;

    printf("Initializing DPDK EAL...\n");
    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        printf("EAL initialization failed: %d\n", ret);
        return -1;
    }

    printf("EAL initialized successfully\n");

    nb_ports = rte_eth_dev_count_avail();

    if (nb_ports == 0) {
        printf("No Ethernet ports found!\n");
        printf("Make sure to use: --vdev='net_enetfec'\n");
        return -1;
    } else {
        printf("Available Ethernet ports: %u\n", nb_ports);
    }

    ret = rte_eth_dev_is_valid_port(DPDK_PORT);
    if (ret == 0) {
        printf("The target port %u is not valid\n", DPDK_PORT);
        return -1;
    }

    // Allocate rx mempool
    assert((pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_rx_pool",
                                                   NUM_MBUFS,
                                                   MBUF_CACHE_SIZE,
                                                   0,
                                                   RTE_MBUF_DEFAULT_BUF_SIZE,
                                                   rte_socket_id())) != NULL);
    if (pktmbuf_pool == NULL) {
        printf("Failed to create mbufpool\n");
        return -1;
    }

    // Allocate tx mempool
    assert((tx_mbuf_pool = rte_pktmbuf_pool_create("mbuf_tx_pool",
                                                   NUM_MBUFS,
                                                   MBUF_CACHE_SIZE,
                                                   0,
                                                   RTE_MBUF_DEFAULT_BUF_SIZE,
                                                   rte_socket_id())) != NULL);
    if (pktmbuf_pool == NULL) {
        printf("Failed to create mbufpool\n");
        return -1;
    }


    ret = port_init(DPDK_PORT, pktmbuf_pool);
    if (ret != 0) {
        printf("Faield to init port %u\n", DPDK_PORT);
        return -1;
    }
    printf("ENETFEC initialisation successful!\n");

    print_dev_info(DPDK_PORT);
    run_udp_echoserver(DPDK_PORT);
    /* run_udp_sender(DPDK_PORT); */

    printf("Stopping port %u...\n", DPDK_PORT);
    ret = rte_eth_dev_stop(DPDK_PORT);
    if (ret != 0) {
        printf("Failed to stop port %u: %s\n", DPDK_PORT, strerror(-ret));
    } else {
        printf("Port %u stopped successfully\n", DPDK_PORT);
    }

    printf("Closing port %u...\n", DPDK_PORT);
    ret = rte_eth_dev_close(DPDK_PORT);
    if (ret != 0) {
        printf("Failed to close port %u: %d\n", DPDK_PORT, ret);
    }

    // Final cleanup
    ret = rte_eal_cleanup();
    if (ret != 0) {
        printf("EAL cleanup failed: %d\n", ret);
    } else {
        printf("EAL cleanup successful\n");
    }

    return 0;
}
