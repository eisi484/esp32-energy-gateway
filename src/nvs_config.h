#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

/**
 * @brief Central gateway configuration stored in NVS flash.
 *        All fields are loaded at boot; changes require reboot.
 */
typedef struct {
    /* Huawei SUN2000 SDongle */
    char     huawei_ip[32];       /**< IP of the SDongle, e.g. "192.168.1.100" */
    uint16_t huawei_port;         /**< Modbus TCP port (default: 502) */
    uint8_t  huawei_slave_id;     /**< Modbus unit/slave ID for Inverter 1 (default: 1) */
    uint8_t  huawei_slave_id_2;   /**< Modbus unit/slave ID for Inverter 2 (default: 2, 0 = disabled) */
    uint16_t modbus_cache_ms;     /**< Cache refresh interval in ms (default: 5000) */
    uint16_t modbus_max_age_ms;   /**< Max age before reporting 0x0B exception (default: 15000) */
    uint8_t  modbus_allow_writes; /**< 0 = reject FC06/16 with exception, 1 = allow whitelisted */
    uint16_t modbus_proxy_port;   /**< Port the ESP32 listens on for Modbus clients */

    /* Shelly 3 EM (Gen1) source */
    char     shelly_ip[32];       /**< IP of the real Shelly 3 EM */
    char     shelly_user[32];     /**< Optional HTTP Basic Auth username for Shelly */
    char     shelly_pass[32];     /**< Optional HTTP Basic Auth password for Shelly */
    uint16_t shelly_poll_ms;      /**< HTTP poll interval in ms (default: 1000) */
    uint8_t  phase_map[3];        /**< phase_map[A/B/C] = emeter index (0/1/2) */
    uint8_t  meter_fallback_enabled; /**< 1 = fallback to Huawei DTSU666 on Shelly loss, 0 = disabled */

    /* Shelly 3 Pro EM emulator output */
    uint16_t shelly_udp_port;     /**< UDP port for Marstek Venus E (default: 2220) */

    /* Embedded MQTT Broker (Port 1883) */
    uint8_t  mqtt_broker_enabled; /**< 1 = run embedded MQTT broker on port 1883, 0 = disabled */
    uint16_t mqtt_broker_port;    /**< MQTT port (default: 1883) */
    char     mqtt_user[32];       /**< Optional MQTT user (empty = allow anonymous) */
    char     mqtt_pass[32];       /**< Optional MQTT password */
    uint8_t  shelly_source_mode;  /**< 0 = HTTP polling only, 1 = Hybrid (MQTT primary, HTTP fallback) */

    /* Security */
    char     admin_password[32];  /**< Legacy admin password (empty if salted hash is used) */
    char     admin_pw_salt[17];   /**< 16-hex character salt (8 bytes) */
    char     admin_pw_hash[65];   /**< 64-hex character SHA-256 hash */

    /* Network */
    uint8_t  use_static_ip;       /**< 0 = DHCP, 1 = static */
    char     static_ip[32];
    char     static_gw[32];
    char     static_nm[32];
} gateway_config_t;

/** Global config instance, loaded once in app_main before tasks start */
extern gateway_config_t g_cfg;

/**
 * @brief Initialize NVS flash and load config into g_cfg.
 *        Must be called before any other config function.
 */
esp_err_t config_init(void);

/**
 * @brief Save a new config to NVS (replaces g_cfg after reboot).
 */
esp_err_t config_save(const gateway_config_t *cfg);

/**
 * @brief Fill cfg with factory defaults (does not write to NVS).
 */
void config_defaults(gateway_config_t *cfg);
