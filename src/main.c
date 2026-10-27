#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/timers.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_ota_ops.h"

#include "nvs_config.h"
#include "data_store.h"
#include "eth_init.h"
#include "shelly_client.h"
#include "shelly_udp_server.h"
#include "http_server.h"
#include "modbus_proxy.h"

static const char *TAG = "main";

/* Timer callback: confirm OTA image after 30s stable runtime */
static void ota_confirm_timer_cb(TimerHandle_t xTimer)
{
    (void)xTimer;
    esp_ota_img_states_t ota_state;
    const esp_partition_t *running = esp_ota_get_running_partition();
    if (esp_ota_get_state_partition(running, &ota_state) == ESP_OK) {
        if (ota_state == ESP_OTA_IMG_PENDING_VERIFY) {
            ESP_LOGI(TAG, "Self-test passed (30s stable runtime). Confirming OTA image and cancelling rollback.");
            esp_ota_mark_app_valid_cancel_rollback();
        }
    }
}

void app_main(void) {
    ESP_LOGI(TAG, "=== ESP32 Energy Gateway starting ===");

    /* 1. Initialize NVS and load config */
    ESP_ERROR_CHECK(config_init());

    /* 2. Initialize shared data store */
    data_store_init();

    /* 3. Initialize Ethernet (WT32-ETH01 / LAN8720) */
    ESP_ERROR_CHECK(eth_init());

    ESP_LOGI(TAG, "Waiting for Ethernet link...");
    esp_err_t err = eth_wait_connected(15000);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Ethernet not connected after 15s — starting services anyway");
    } else {
        ESP_LOGI(TAG, "Ethernet connected: %s", g_data.eth_ip);
    }

    /* 4. Start HTTP server (config portal + Shelly API + OTA) */
    ESP_ERROR_CHECK(http_server_start());

    /* 5. Start Shelly 3 EM poller */
    shelly_client_start();

    /* 6. Start Shelly Pro 3EM UDP server (for Marstek Venus E) */
    shelly_udp_server_start();

    /* 7. Start Modbus TCP caching proxy (for EVCC + ioBroker) */
    modbus_proxy_start();

    /* 8. Start OTA confirmation timer (30s delay) */
    TimerHandle_t ota_timer = xTimerCreate("ota_confirm", pdMS_TO_TICKS(30000),
                                           pdFALSE, NULL, ota_confirm_timer_cb);
    if (ota_timer) {
        xTimerStart(ota_timer, 0);
    }

    ESP_LOGI(TAG, "All services started.");
    ESP_LOGI(TAG, "  Web config:   http://%s/config", g_data.eth_ip);
    ESP_LOGI(TAG, "  Hostname:     http://esp32-energy-gateway.local/config");
    ESP_LOGI(TAG, "  Shelly API:   http://%s/rpc/EM.GetStatus", g_data.eth_ip);
    ESP_LOGI(TAG, "  Modbus proxy: %s:%u", g_data.eth_ip, g_cfg.modbus_proxy_port);
    ESP_LOGI(TAG, "  Shelly UDP:   %s:%u (Marstek Venus E)", g_data.eth_ip, g_cfg.shelly_udp_port);
}
