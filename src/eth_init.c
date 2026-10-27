/*
 * eth_init.c
 *
 * Ethernet initialisation for the WT32-ETH01 board (LAN8720 PHY).
 *
 * Pin mapping
 * -----------
 *  GPIO 16  – PHY power enable (active HIGH, must be set before PHY init)
 *  GPIO  0  – RMII REF_CLK input  (external 50 MHz oscillator on LAN8720)
 *  GPIO 23  – RMII MDC
 *  GPIO 18  – RMII MDIO
 *  GPIO 32  – CFG pin: Recovery Jumper (internal pull-up, GND = force DHCP)
 *  PHY addr – 1
 *  PHY reset– none (-1)
 */

#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "driver/gpio.h"
#include "esp_eth.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "esp_log.h"
#include "lwip/ip4_addr.h"

#include "data_store.h"
#include "nvs_config.h"
#include "eth_init.h"

/* ── Constants ─────────────────────────────────────────────────────────── */

#define TAG                 "eth_init"

#define ETH_PHY_POWER_GPIO  16      /* HIGH → PHY powered */
#define ETH_MDC_GPIO        23
#define ETH_MDIO_GPIO       18
#define ETH_PHY_ADDR        1
#define ETH_PHY_RST_GPIO    (-1)    /* no hardware reset pin */
#define ETH_RECOVERY_GPIO   32      /* CFG pin on WT32-ETH01 */

/* EventGroup bit set once we have an IP address */
#define ETH_CONNECTED_BIT   BIT0

/* ── Module-private state ────────────────────────────────────────────────── */

static const char *TAG_LOCAL = TAG;
static EventGroupHandle_t eth_event_group;
static esp_netif_t       *s_eth_netif = NULL;
static bool               s_recovery_active = false;

/* ── Event handlers ──────────────────────────────────────────────────────── */

static void eth_event_handler(void *arg, esp_event_base_t event_base,
                              int32_t event_id, void *event_data)
{
    (void)arg;
    (void)event_base;
    (void)event_data;

    switch ((eth_event_t)event_id) {
    case ETHERNET_EVENT_CONNECTED:
        ESP_LOGI(TAG_LOCAL, "Ethernet link up");
        /* If static IP is active, LwIP does not trigger DHCP got_ip; update status here */
        if (g_cfg.use_static_ip == 1 && !s_recovery_active) {
            DATA_LOCK();
            g_data.eth_connected = true;
            strncpy(g_data.eth_ip, g_cfg.static_ip, sizeof(g_data.eth_ip) - 1);
            g_data.eth_ip[sizeof(g_data.eth_ip) - 1] = '\0';
            DATA_UNLOCK();
            xEventGroupSetBits(eth_event_group, ETH_CONNECTED_BIT);
            ESP_LOGI(TAG_LOCAL, "Static IP active on link-up: %s", g_cfg.static_ip);
        }
        break;

    case ETHERNET_EVENT_DISCONNECTED:
        ESP_LOGW(TAG_LOCAL, "Ethernet link down");
        DATA_LOCK();
        g_data.eth_connected = false;
        g_data.eth_ip[0]     = '\0';
        DATA_UNLOCK();
        xEventGroupClearBits(eth_event_group, ETH_CONNECTED_BIT);
        break;

    default:
        break;
    }
}

static void ip_event_handler(void *arg, esp_event_base_t event_base,
                             int32_t event_id, void *event_data)
{
    (void)arg;
    (void)event_base;

    if ((ip_event_t)event_id != IP_EVENT_ETH_GOT_IP) {
        return;
    }

    ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
    char ip_str[16];
    esp_ip4addr_ntoa(&event->ip_info.ip, ip_str, sizeof(ip_str));

    ESP_LOGI(TAG_LOCAL, "Ethernet got IP: %s (hostname: esp32-energy-gateway)", ip_str);

    DATA_LOCK();
    g_data.eth_connected = true;
    strncpy(g_data.eth_ip, ip_str, sizeof(g_data.eth_ip) - 1);
    g_data.eth_ip[sizeof(g_data.eth_ip) - 1] = '\0';
    DATA_UNLOCK();

    xEventGroupSetBits(eth_event_group, ETH_CONNECTED_BIT);
}

/* ── Static-IP helper ────────────────────────────────────────────────────── */

static void apply_static_ip(void)
{
    if (s_eth_netif == NULL) return;

    esp_err_t err = esp_netif_dhcpc_stop(s_eth_netif);
    if (err != ESP_OK && err != ESP_ERR_ESP_NETIF_DHCP_ALREADY_STOPPED) {
        ESP_LOGW(TAG_LOCAL, "esp_netif_dhcpc_stop: %s", esp_err_to_name(err));
    }

    esp_netif_ip_info_t ip_info;
    memset(&ip_info, 0, sizeof(ip_info));

    if (esp_netif_str_to_ip4(g_cfg.static_ip, &ip_info.ip) != ESP_OK ||
        esp_netif_str_to_ip4(g_cfg.static_gw, &ip_info.gw) != ESP_OK ||
        esp_netif_str_to_ip4(g_cfg.static_nm, &ip_info.netmask) != ESP_OK) {
        ESP_LOGE(TAG_LOCAL, "Invalid static IP configuration: ip=%s gw=%s nm=%s",
                 g_cfg.static_ip, g_cfg.static_gw, g_cfg.static_nm);
        return;
    }

    err = esp_netif_set_ip_info(s_eth_netif, &ip_info);
    if (err != ESP_OK) {
        ESP_LOGE(TAG_LOCAL, "esp_netif_set_ip_info: %s", esp_err_to_name(err));
        return;
    }

    ESP_LOGI(TAG_LOCAL, "Static IP configured: %s / %s  gw %s",
             g_cfg.static_ip, g_cfg.static_nm, g_cfg.static_gw);
}

/* ── Public API ──────────────────────────────────────────────────────────── */

esp_err_t eth_init(void)
{
    /* ── Check Recovery Jumper on GPIO32 (CFG pin on WT32-ETH01) ── */
    gpio_config_t rec_cfg = {
        .pin_bit_mask = (1ULL << ETH_RECOVERY_GPIO),
        .mode         = GPIO_MODE_INPUT,
        .pull_up_en   = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    gpio_config(&rec_cfg);
    vTaskDelay(pdMS_TO_TICKS(10));

    if (gpio_get_level(ETH_RECOVERY_GPIO) == 0) {
        s_recovery_active = true;
        g_cfg.admin_password[0] = '\0'; /* Reset password for this session */
        g_cfg.admin_pw_hash[0]  = '\0';
        g_cfg.admin_pw_salt[0]  = '\0';
        ESP_LOGW(TAG_LOCAL, "*******************************************************");
        ESP_LOGW(TAG_LOCAL, "*** RECOVERY MODE: GPIO32 (CFG) is grounded!        ***");
        ESP_LOGW(TAG_LOCAL, "*** Forcing DHCP and resetting admin password in RAM***");
        ESP_LOGW(TAG_LOCAL, "*******************************************************");
    }

    /* Create the EventGroup used by eth_wait_connected() */
    eth_event_group = xEventGroupCreate();
    configASSERT(eth_event_group);

    /* ── 1. TCP/IP stack + netif ──────────────────────────────────────── */
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    esp_netif_config_t netif_cfg = ESP_NETIF_DEFAULT_ETH();
    s_eth_netif = esp_netif_new(&netif_cfg);
    configASSERT(s_eth_netif);

    /* Set hostname in DHCP */
    esp_netif_set_hostname(s_eth_netif, "esp32-energy-gateway");

    /* ── 2. PHY power-enable GPIO ─────────────────────────────────────── */
    gpio_config_t pwr_cfg = {
        .pin_bit_mask = (1ULL << ETH_PHY_POWER_GPIO),
        .mode         = GPIO_MODE_OUTPUT,
        .pull_up_en   = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    ESP_ERROR_CHECK(gpio_config(&pwr_cfg));
    ESP_ERROR_CHECK(gpio_set_level(ETH_PHY_POWER_GPIO, 1));
    vTaskDelay(pdMS_TO_TICKS(10));

    /* ── 3. MAC ───────────────────────────────────────────────────────── */
    eth_mac_config_t mac_cfg = ETH_MAC_DEFAULT_CONFIG();
    eth_esp32_emac_config_t emac_cfg = ETH_ESP32_EMAC_DEFAULT_CONFIG();
    emac_cfg.smi_gpio.mdc_num  = ETH_MDC_GPIO;
    emac_cfg.smi_gpio.mdio_num = ETH_MDIO_GPIO;
    emac_cfg.clock_config.rmii.clock_mode = EMAC_CLK_EXT_IN;
    emac_cfg.clock_config.rmii.clock_gpio = EMAC_CLK_IN_GPIO; /* GPIO0 */

    esp_eth_mac_t *mac = esp_eth_mac_new_esp32(&emac_cfg, &mac_cfg);
    configASSERT(mac);

    /* ── 4. PHY (LAN8720) ─────────────────────────────────────────────── */
    eth_phy_config_t phy_cfg = ETH_PHY_DEFAULT_CONFIG();
    phy_cfg.phy_addr      = ETH_PHY_ADDR;
    phy_cfg.reset_gpio_num = ETH_PHY_RST_GPIO;

    esp_eth_phy_t *phy = esp_eth_phy_new_lan87xx(&phy_cfg);
    configASSERT(phy);

    /* ── 5. Ethernet driver ───────────────────────────────────────────── */
    esp_eth_config_t eth_cfg = ETH_DEFAULT_CONFIG(mac, phy);
    esp_eth_handle_t eth_handle = NULL;
    ESP_ERROR_CHECK(esp_eth_driver_install(&eth_cfg, &eth_handle));

    esp_eth_netif_glue_handle_t glue = esp_eth_new_netif_glue(eth_handle);
    ESP_ERROR_CHECK(esp_netif_attach(s_eth_netif, glue));

    /* ── 6. Static IP (skipped if recovery jumper active) ─────────────── */
    if (g_cfg.use_static_ip == 1 && !s_recovery_active) {
        apply_static_ip();
    }

    /* ── 7. Event handlers ────────────────────────────────────────────── */
    ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT,
                                               ESP_EVENT_ANY_ID,
                                               &eth_event_handler,
                                               NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT,
                                               IP_EVENT_ETH_GOT_IP,
                                               &ip_event_handler,
                                               NULL));

    /* ── 8. Start Ethernet driver ─────────────────────────────────────── */
    ESP_ERROR_CHECK(esp_eth_start(eth_handle));
    ESP_LOGI(TAG_LOCAL, "Ethernet initialised (WT32-ETH01 LAN8720)");
    return ESP_OK;
}

esp_err_t eth_wait_connected(uint32_t timeout_ms)
{
    if (eth_event_group == NULL) return ESP_ERR_INVALID_STATE;

    TickType_t ticks = (timeout_ms == 0) ? portMAX_DELAY : pdMS_TO_TICKS(timeout_ms);
    EventBits_t bits = xEventGroupWaitBits(eth_event_group,
                                           ETH_CONNECTED_BIT,
                                           pdFALSE,
                                           pdTRUE,
                                           ticks);
    return (bits & ETH_CONNECTED_BIT) ? ESP_OK : ESP_ERR_TIMEOUT;
}
