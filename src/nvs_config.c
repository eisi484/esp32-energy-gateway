#include <string.h>
#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "nvs_config.h"

static const char *TAG = "nvs_config";
#define NS "gw"

gateway_config_t g_cfg;

void config_defaults(gateway_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    strlcpy(cfg->huawei_ip,  "0.0.0.0",       sizeof(cfg->huawei_ip));
    cfg->huawei_port        = 502;
    cfg->huawei_slave_id    = 1;
    cfg->huawei_slave_id_2  = 2;
    cfg->modbus_cache_ms    = 5000;
    cfg->modbus_max_age_ms  = 15000;
    cfg->modbus_allow_writes = 0;
    cfg->modbus_proxy_port  = 502;
    strlcpy(cfg->shelly_ip,  "0.0.0.0",       sizeof(cfg->shelly_ip));
    cfg->shelly_poll_ms     = 1000;
    cfg->phase_map[0]       = 0;
    cfg->phase_map[1]       = 1;
    cfg->phase_map[2]       = 2;
    cfg->meter_fallback_enabled = 1;
    cfg->shelly_udp_port    = 2220;
    cfg->admin_password[0]  = '\0';
    cfg->use_static_ip      = 0;
    strlcpy(cfg->static_ip,  "192.168.1.50",  sizeof(cfg->static_ip));
    strlcpy(cfg->static_gw,  "192.168.1.1",   sizeof(cfg->static_gw));
    strlcpy(cfg->static_nm,  "255.255.255.0", sizeof(cfg->static_nm));
}

esp_err_t config_init(void) {
    /* Initialize NVS flash */
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "NVS partition truncated, erasing...");
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    if (err != ESP_OK) return err;

    config_defaults(&g_cfg);

    nvs_handle_t h;
    err = nvs_open(NS, NVS_READONLY, &h);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        ESP_LOGI(TAG, "No saved config — using factory defaults");
        return ESP_OK;
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_open failed: %s", esp_err_to_name(err));
        return err;
    }

    size_t len;
    uint16_t u16;
    uint8_t  u8;

#define NVS_GET_STR(key, field) \
    do { len = sizeof(g_cfg.field); nvs_get_str(h, key, g_cfg.field, &len); } while(0)
#define NVS_GET_U16(key, field) \
    do { if (nvs_get_u16(h, key, &u16) == ESP_OK) g_cfg.field = u16; } while(0)
#define NVS_GET_U8(key, field) \
    do { if (nvs_get_u8(h, key, &u8) == ESP_OK)  g_cfg.field = u8;  } while(0)

    NVS_GET_STR("h_ip",    huawei_ip);
    NVS_GET_U16("h_port",  huawei_port);
    NVS_GET_U8 ("h_sid",   huawei_slave_id);
    NVS_GET_U8 ("h_sid2",  huawei_slave_id_2);
    NVS_GET_U16("h_cache", modbus_cache_ms);
    NVS_GET_U16("mb_maxage",modbus_max_age_ms);
    NVS_GET_U8 ("mb_writes",modbus_allow_writes);
    NVS_GET_U16("mb_port", modbus_proxy_port);
    NVS_GET_STR("s_ip",    shelly_ip);
    NVS_GET_STR("s_usr",   shelly_user);
    NVS_GET_STR("s_pwd",   shelly_pass);
    NVS_GET_U16("s_poll",  shelly_poll_ms);
    NVS_GET_U8 ("s_pa",    phase_map[0]);
    NVS_GET_U8 ("s_pb",    phase_map[1]);
    NVS_GET_U8 ("s_pc",    phase_map[2]);
    NVS_GET_U8 ("m_fb",    meter_fallback_enabled);
    NVS_GET_U16("udp_port",shelly_udp_port);
    NVS_GET_STR("adm_pw",  admin_password);
    NVS_GET_STR("pw_salt", admin_pw_salt);
    NVS_GET_STR("pw_hash", admin_pw_hash);
    NVS_GET_U8 ("use_sip", use_static_ip);
    NVS_GET_STR("sip",     static_ip);
    NVS_GET_STR("sgw",     static_gw);
    NVS_GET_STR("snm",     static_nm);

#undef NVS_GET_STR
#undef NVS_GET_U16
#undef NVS_GET_U8

    nvs_close(h);
    ESP_LOGI(TAG, "Config loaded: huawei=%s:%u sid=%u, shelly=%s poll=%ums",
             g_cfg.huawei_ip, g_cfg.huawei_port, g_cfg.huawei_slave_id,
             g_cfg.shelly_ip, g_cfg.shelly_poll_ms);
    return ESP_OK;
}

esp_err_t config_save(const gateway_config_t *cfg) {
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;

    nvs_set_str(h, "h_ip",    cfg->huawei_ip);
    nvs_set_u16(h, "h_port",  cfg->huawei_port);
    nvs_set_u8 (h, "h_sid",   cfg->huawei_slave_id);
    nvs_set_u8 (h, "h_sid2",  cfg->huawei_slave_id_2);
    nvs_set_u16(h, "h_cache", cfg->modbus_cache_ms);
    nvs_set_u16(h, "mb_maxage",cfg->modbus_max_age_ms);
    nvs_set_u8 (h, "mb_writes",cfg->modbus_allow_writes);
    nvs_set_u16(h, "mb_port", cfg->modbus_proxy_port);
    nvs_set_str(h, "s_ip",    cfg->shelly_ip);
    nvs_set_str(h, "s_usr",   cfg->shelly_user);
    nvs_set_str(h, "s_pwd",   cfg->shelly_pass);
    nvs_set_u16(h, "s_poll",  cfg->shelly_poll_ms);
    nvs_set_u8 (h, "s_pa",    cfg->phase_map[0]);
    nvs_set_u8 (h, "s_pb",    cfg->phase_map[1]);
    nvs_set_u8 (h, "s_pc",    cfg->phase_map[2]);
    nvs_set_u8 (h, "m_fb",    cfg->meter_fallback_enabled);
    nvs_set_u16(h, "udp_port",cfg->shelly_udp_port);
    nvs_set_str(h, "adm_pw",  cfg->admin_password);
    nvs_set_str(h, "pw_salt", cfg->admin_pw_salt);
    nvs_set_str(h, "pw_hash", cfg->admin_pw_hash);
    nvs_set_u8 (h, "use_sip", cfg->use_static_ip);
    nvs_set_str(h, "sip",     cfg->static_ip);
    nvs_set_str(h, "sgw",     cfg->static_gw);
    nvs_set_str(h, "snm",     cfg->static_nm);

    err = nvs_commit(h);
    nvs_close(h);
    if (err == ESP_OK)
        ESP_LOGI(TAG, "Config saved to NVS");
    else
        ESP_LOGE(TAG, "nvs_commit failed: %s", esp_err_to_name(err));
    return err;
}
