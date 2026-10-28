/*
 * shelly_client.c
 *
 * FreeRTOS task that polls a Shelly 3 EM (Gen 1) over HTTP and writes
 * three-phase power data and double-precision energy counters into the
 * shared g_data store.
 *
 * Endpoint polled : GET http://<g_cfg.shelly_ip>/status
 * Poll interval   : g_cfg.shelly_poll_ms milliseconds
 * Phase mapping   : g_cfg.phase_map[0/1/2] maps emeter index → phase A/B/C
 */

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "cJSON.h"
#include "data_store.h"
#include "nvs_config.h"
#include "modbus_proxy.h"
#include "shelly_client.h"

#define TAG               "shelly_client"
#define RESPONSE_BUF_SIZE 4096
#define TASK_STACK_SIZE   (8 * 1024)
#define TASK_PRIORITY     5
#define NUM_PHASES        3
#define DEFAULT_FREQ_HZ   50.0f
#define HTTP_TIMEOUT_MS   3000

typedef struct {
    char buf[RESPONSE_BUF_SIZE];
    int  len;
    bool overflow;
} http_resp_t;

static esp_err_t http_event_handler(esp_http_client_event_t *evt)
{
    http_resp_t *resp = (http_resp_t *)evt->user_data;
    switch (evt->event_id) {
    case HTTP_EVENT_ON_DATA:
        if (!resp->overflow) {
            if (resp->len + evt->data_len >= (int)sizeof(resp->buf)) {
                resp->overflow = true;
            } else {
                memcpy(resp->buf + resp->len, evt->data, evt->data_len);
                resp->len += evt->data_len;
            }
        }
        break;
    case HTTP_EVENT_ON_FINISH:
        if (resp->len < (int)sizeof(resp->buf))
            resp->buf[resp->len] = '\0';
        else
            resp->buf[sizeof(resp->buf)-1] = '\0';
        break;
    case HTTP_EVENT_ERROR:
        ESP_LOGD(TAG, "HTTP error event");
        break;
    default:
        break;
    }
    return ESP_OK;
}

/* Per-phase temp buffer with double-precision for energy counters */
typedef struct {
    float  power, pf, current, voltage, reactive, aprt_power;
    double total, total_returned;
    bool   is_valid;
} phase_tmp_t;

static bool parse_and_store(const char *json_str)
{
    bool ok = false;
    cJSON *root = cJSON_Parse(json_str);
    if (!root) { ESP_LOGW(TAG, "cJSON_Parse failed"); return false; }

    cJSON *emeters = cJSON_GetObjectItemCaseSensitive(root, "emeters");
    if (!cJSON_IsArray(emeters) || cJSON_GetArraySize(emeters) < NUM_PHASES) {
        ESP_LOGW(TAG, "\"emeters\" missing or too short");
        goto cleanup;
    }

    cJSON *tp_item = cJSON_GetObjectItemCaseSensitive(root, "total_power");
    float total_power = cJSON_IsNumber(tp_item) ? (float)tp_item->valuedouble : 0.0f;

#define GF(obj, key, out, fb) \
    do { cJSON *_i = cJSON_GetObjectItemCaseSensitive((obj),(key)); \
         (out) = cJSON_IsNumber(_i) ? (float)_i->valuedouble : (fb); } while(0)

#define GD(obj, key, out, fb) \
    do { cJSON *_i = cJSON_GetObjectItemCaseSensitive((obj),(key)); \
         (out) = cJSON_IsNumber(_i) ? (double)_i->valuedouble : (fb); } while(0)

    phase_tmp_t ph[NUM_PHASES];
    bool all_valid = true;
    for (int p = 0; p < NUM_PHASES; p++) {
        int idx = (int)g_cfg.phase_map[p];
        cJSON *em = cJSON_GetArrayItem(emeters, idx);
        if (!em) {
            ESP_LOGW(TAG, "phase %d: emeter[%d] missing", p, idx);
            memset(&ph[p], 0, sizeof(ph[p]));
            all_valid = false;
            continue;
        }
        GF(em, "power",          ph[p].power,          0.0f);
        GF(em, "pf",             ph[p].pf,             0.0f);
        GF(em, "current",        ph[p].current,        0.0f);
        GF(em, "voltage",        ph[p].voltage,        0.0f);
        GF(em, "reactive",       ph[p].reactive,       0.0f);
        GD(em, "total",          ph[p].total,          0.0);
        GD(em, "total_returned", ph[p].total_returned, 0.0);
        cJSON *iv = cJSON_GetObjectItemCaseSensitive(em, "is_valid");
        ph[p].is_valid   = cJSON_IsBool(iv) ? cJSON_IsTrue(iv) : false;
        ph[p].aprt_power = ph[p].voltage * ph[p].current;
        if (!ph[p].is_valid) all_valid = false;
    }
#undef GF
#undef GD

    /* Write fields in g_data */
    if (DATA_LOCK()) {
        /* Phase A */
        g_data.a_act_power  = ph[0].power;
        g_data.a_pf         = ph[0].pf;
        g_data.a_current    = ph[0].current;
        g_data.a_voltage    = ph[0].voltage;
        g_data.a_aprt_power = ph[0].aprt_power;
        g_data.a_freq       = DEFAULT_FREQ_HZ;
        g_data.a_total_wh   = ph[0].total;
        g_data.a_total_ret_wh = ph[0].total_returned;

        /* Phase B */
        g_data.b_act_power  = ph[1].power;
        g_data.b_pf         = ph[1].pf;
        g_data.b_current    = ph[1].current;
        g_data.b_voltage    = ph[1].voltage;
        g_data.b_aprt_power = ph[1].aprt_power;
        g_data.b_freq       = DEFAULT_FREQ_HZ;
        g_data.b_total_wh   = ph[1].total;
        g_data.b_total_ret_wh = ph[1].total_returned;

        /* Phase C */
        g_data.c_act_power  = ph[2].power;
        g_data.c_pf         = ph[2].pf;
        g_data.c_current    = ph[2].current;
        g_data.c_voltage    = ph[2].voltage;
        g_data.c_aprt_power = ph[2].aprt_power;
        g_data.c_freq       = DEFAULT_FREQ_HZ;
        g_data.c_total_wh   = ph[2].total;
        g_data.c_total_ret_wh = ph[2].total_returned;

        /* Totals */
        g_data.total_act_power   = total_power;
        g_data.total_aprt_power  = ph[0].aprt_power + ph[1].aprt_power + ph[2].aprt_power;
        g_data.total_current     = ph[0].current + ph[1].current + ph[2].current;
        g_data.total_act_wh      = ph[0].total + ph[1].total + ph[2].total;
        g_data.total_act_ret_wh  = ph[0].total_returned + ph[1].total_returned + ph[2].total_returned;

        g_data.shelly_valid      = all_valid;
        g_data.shelly_last_update_ms = (int64_t)(esp_timer_get_time() / 1000ULL);
        g_data.active_meter_source = all_valid ? METER_SRC_SHELLY : METER_SRC_NONE;
        DATA_UNLOCK();
    }

    ok = true;
cleanup:
    cJSON_Delete(root);
    return ok;
}

static void shelly_client_task(void *pvParameters)
{
    (void)pvParameters;

    if (g_cfg.shelly_ip[0] == '\0' || strcmp(g_cfg.shelly_ip, "0.0.0.0") == 0) {
        ESP_LOGW(TAG, "Shelly IP not configured – task suspended");
        vTaskSuspend(NULL);
    }

    char url[128];
    snprintf(url, sizeof(url), "http://%s/status", g_cfg.shelly_ip);
    ESP_LOGI(TAG, "Polling %s every %u ms (timeout: %u ms)",
             url, g_cfg.shelly_poll_ms, HTTP_TIMEOUT_MS);

    static http_resp_t resp; /* static: keeps buffer off the task stack */

    for (;;) {
        /* If Hybrid mode is active and fresh MQTT messages were received within 2500ms,
         * skip HTTP polling to relieve the Shelly 3 EM CPU and Wi-Fi */
        if (g_cfg.shelly_source_mode == 1) {
            int64_t now_check_ms = esp_timer_get_time() / 1000LL;
            bool mqtt_fresh = false;
            if (DATA_LOCK()) {
                if (g_data.active_meter_source == METER_SRC_MQTT &&
                    g_data.shelly_valid &&
                    g_data.mqtt_last_rx_ms > 0 &&
                    (now_check_ms - g_data.mqtt_last_rx_ms) < 2500LL) {
                    mqtt_fresh = true;
                }
                DATA_UNLOCK();
            }
            if (mqtt_fresh) {
                vTaskDelay(pdMS_TO_TICKS(500));
                continue;
            }
        }

        resp.len      = 0;
        resp.overflow = false;
        memset(resp.buf, 0, sizeof(resp.buf));

        esp_http_client_config_t http_cfg = {
            .url           = url,
            .method        = HTTP_METHOD_GET,
            .timeout_ms    = HTTP_TIMEOUT_MS,
            .event_handler = http_event_handler,
            .user_data     = &resp,
            .username      = (g_cfg.shelly_user[0] != '\0') ? g_cfg.shelly_user : NULL,
            .password      = (g_cfg.shelly_user[0] != '\0') ? g_cfg.shelly_pass : NULL,
            .auth_type     = (g_cfg.shelly_user[0] != '\0') ? HTTP_AUTH_TYPE_BASIC : HTTP_AUTH_TYPE_NONE,
        };

        const char *err_reason = NULL;
        char err_detail[64] = {0};

        esp_http_client_handle_t client = esp_http_client_init(&http_cfg);
        if (!client) {
            ESP_LOGW(TAG, "esp_http_client_init failed");
            err_reason = "client_init_failed";
            goto set_invalid;
        }

        int64_t t_start = esp_timer_get_time();
        esp_err_t err = esp_http_client_perform(client);
        int64_t elapsed_ms = (esp_timer_get_time() - t_start) / 1000LL;
        int status   = esp_http_client_get_status_code(client);
        esp_http_client_cleanup(client);

        if (err != ESP_OK) {
            ESP_LOGW(TAG, "HTTP GET failed after %lld ms: %s", elapsed_ms, esp_err_to_name(err));
            snprintf(err_detail, sizeof(err_detail), "%s (%lldms)", esp_err_to_name(err), elapsed_ms);
            err_reason = err_detail;
            goto set_invalid;
        }
        if (status != 200) {
            ESP_LOGW(TAG, "HTTP status %d after %lld ms", status, elapsed_ms);
            snprintf(err_detail, sizeof(err_detail), "HTTP %d (%lldms)", status, elapsed_ms);
            err_reason = err_detail;
            goto set_invalid;
        }
        if (resp.overflow) {
            ESP_LOGW(TAG, "Response truncated (>%d bytes)", RESPONSE_BUF_SIZE);
            err_reason = "overflow";
            goto set_invalid;
        }
        if (!parse_and_store(resp.buf)) {
            err_reason = "parse_failed";
            goto set_invalid;
        }

        static int fail_count = 0;

        if (DATA_LOCK()) {
            fail_count = 0;
            g_data.sh_err[0] = '\0';
            DATA_UNLOCK();
        }
        goto next_poll;

    set_invalid:
        if (g_cfg.meter_fallback_enabled) {
            shelly_data_snapshot_t fb;
            if (modbus_proxy_read_meter(&fb)) {
                if (DATA_LOCK()) {
                    g_data.a_voltage        = fb.a_voltage;
                    g_data.a_current        = fb.a_current;
                    g_data.a_act_power      = fb.a_act_power;
                    g_data.a_aprt_power     = fb.a_aprt_power;
                    g_data.a_pf             = fb.a_pf;
                    g_data.a_freq           = fb.a_freq;
                    g_data.a_total_wh       = fb.a_total_wh;
                    g_data.a_total_ret_wh   = fb.a_total_ret_wh;

                    g_data.b_voltage        = fb.b_voltage;
                    g_data.b_current        = fb.b_current;
                    g_data.b_act_power      = fb.b_act_power;
                    g_data.b_aprt_power     = fb.b_aprt_power;
                    g_data.b_pf             = fb.b_pf;
                    g_data.b_freq           = fb.b_freq;
                    g_data.b_total_wh       = fb.b_total_wh;
                    g_data.b_total_ret_wh   = fb.b_total_ret_wh;

                    g_data.c_voltage        = fb.c_voltage;
                    g_data.c_current        = fb.c_current;
                    g_data.c_act_power      = fb.c_act_power;
                    g_data.c_aprt_power     = fb.c_aprt_power;
                    g_data.c_pf             = fb.c_pf;
                    g_data.c_freq           = fb.c_freq;
                    g_data.c_total_wh       = fb.c_total_wh;
                    g_data.c_total_ret_wh   = fb.c_total_ret_wh;

                    g_data.total_act_power  = fb.total_act_power;
                    g_data.total_aprt_power = fb.total_aprt_power;
                    g_data.total_current    = fb.total_current;
                    g_data.total_act_wh     = fb.total_act_wh;
                    g_data.total_act_ret_wh = fb.total_act_ret_wh;

                    g_data.shelly_valid     = true;
                    g_data.shelly_last_update_ms = fb.shelly_last_update_ms;
                    g_data.active_meter_source   = METER_SRC_HUAWEI;
                    if (err_reason) {
                        strncpy(g_data.sh_err, err_reason, sizeof(g_data.sh_err) - 1);
                        g_data.sh_err[sizeof(g_data.sh_err) - 1] = '\0';
                    }
                    DATA_UNLOCK();
                }
                goto next_poll;
            }
        }

        if (DATA_LOCK()) {
            fail_count++;
            if (fail_count >= 3) {
                g_data.shelly_valid = false;
                g_data.active_meter_source = METER_SRC_NONE;
            }
            if (err_reason) {
                strncpy(g_data.sh_err, err_reason, sizeof(g_data.sh_err) - 1);
                g_data.sh_err[sizeof(g_data.sh_err) - 1] = '\0';
            }
            DATA_UNLOCK();
        }

    next_poll:
        vTaskDelay(pdMS_TO_TICKS(g_cfg.shelly_poll_ms));
    }
}

void shelly_client_start(void)
{
    BaseType_t ret = xTaskCreate(shelly_client_task, "shelly_client",
                                 TASK_STACK_SIZE, NULL, TASK_PRIORITY, NULL);
    if (ret != pdPASS)
        ESP_LOGE(TAG, "Failed to create shelly_client_task");
    else
        ESP_LOGI(TAG, "shelly_client started");
}
