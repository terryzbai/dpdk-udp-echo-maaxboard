// test_enetfec_fixed.c
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_bus_vdev.h>
#include <stdio.h>
#include <signal.h>

static volatile bool force_quit = false;

static void signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\nSignal %d received, preparing to exit...\n", signum);
        force_quit = true;
    }
}

int main(int argc, char *argv[])
{
    int ret;
    uint16_t nb_ports;

    // Install signal handler
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("Initializing DPDK EAL...\n");
    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        printf("EAL initialization failed: %d\n", ret);
        return -1;
    }

    printf("EAL initialized successfully\n");

    nb_ports = rte_eth_dev_count_avail();
    printf("Available Ethernet ports: %u\n", nb_ports);

    if (nb_ports == 0) {
        printf("No Ethernet ports found!\n");
        printf("Make sure to use: --vdev='net_enetfec'\n");
    } else {
        uint16_t port_id;
        RTE_ETH_FOREACH_DEV(port_id) {
            struct rte_eth_dev_info dev_info;
            struct rte_ether_addr mac_addr;

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
        }
    }

    printf("ENETFEC detection successful!\n");
    printf("Press Ctrl+C to exit...\n");

    // Simple loop instead of immediate cleanup
    while (!force_quit) {
        rte_delay_ms(100);
    }

    printf("Cleaning up...\n");

    // Safer cleanup
    if (nb_ports > 0) {
        uint16_t port_id;
        RTE_ETH_FOREACH_DEV(port_id) {
            printf("Closing port %u...\n", port_id);
            ret = rte_eth_dev_close(port_id);
            if (ret != 0) {
                printf("Failed to close port %u: %d\n", port_id, ret);
            }
        }
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
