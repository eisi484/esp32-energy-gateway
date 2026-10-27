#pragma once
#include "esp_err.h"
#include "esp_netif.h"

/**
 * @brief Initialize WT32-ETH01 Ethernet (LAN8720 on RMII).
 *
 * Pin mapping:
 *   GPIO16  → PHY power enable (active HIGH)
 *   GPIO0   → RMII REF_CLK (50 MHz input from LAN8720 oscillator)
 *   GPIO23  → SMI MDC
 *   GPIO18  → SMI MDIO
 *   PHY addr = 1
 *
 * Registers an IP_EVENT_ETH_GOT_IP handler that:
 *   - Sets g_data.eth_connected = true
 *   - Stores the IP string in g_data.eth_ip
 *   - Sets an EventGroup bit so app_main can wait for connectivity.
 *
 * If use_static_ip is set in g_cfg, configures static IP before DHCP start.
 *
 * @return ESP_OK on success
 */
esp_err_t eth_init(void);

/**
 * @brief Block until Ethernet link is up and an IP address is assigned.
 *        Returns immediately if already connected.
 * @param timeout_ms  Maximum wait time (0 = wait forever)
 * @return ESP_OK if connected, ESP_ERR_TIMEOUT otherwise
 */
esp_err_t eth_wait_connected(uint32_t timeout_ms);
