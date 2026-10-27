/**
 * @file shelly_udp_server.c
 * @brief UDP RPC server emulating a Shelly Pro 3EM (Gen2) device.
 *
 * Listens on g_cfg.shelly_udp_port (default 2220) and responds to
 * JSON-RPC 2.0 method calls:
 *   - EM.GetStatus
 *   - EMData.GetStatus
 *   - Shelly.GetDeviceInfo
 *   - Shelly.GetStatus
 *   - Shelly.GetConfig
 *
 * Staleness Policy:
 *   If sensor data is older than 4000 ms, live telemetry requests
 *   are dropped (no reply) to let the consumer fall into safe timeout.
 *   Unknown methods receive a JSON-RPC "Method not found" error.
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <math.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "lwip/sockets.h"

#include "esp_log.h"
#include "esp_mac.h"
#include "esp_timer.h"

#include "cJSON.h"

#include "data_store.h"
#include "nvs_config.h"
#include "shelly_udp_server.h"

/* ------------------------------------------------------------------ */
/*  Constants                                                           */
/* ------------------------------------------------------------------ */

#define TAG               "shelly_udp"
#define RX_BUF_SIZE       2048
#define TX_BUF_SIZE       2048
#define TASK_STACK_BYTES  6144
#define TASK_PRIORITY     5
#define STALE_THRESHOLD_MS 4000

static char s_mac_str[13]       = "AABBCCDDEEFF";
static char s_mac_str_lower[13] = "aabbccddeeff";
static char s_dev_id[32]        = "shellypro3em-esp32";

static void init_device_identity(void)
{
    uint8_t mac[6];
    if (esp_read_mac(mac, ESP_MAC_ETH) == ESP_OK) {
        snprintf(s_mac_str, sizeof(s_mac_str), "%02X%02X%02X%02X%02X%02X",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        snprintf(s_mac_str_lower, sizeof(s_mac_str_lower), "%02x%02x%02x%02x%02x%02x",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        snprintf(s_dev_id, sizeof(s_dev_id), "shellypro3em-%02x%02x%02x%02x%02x%02x",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
}

/* ------------------------------------------------------------------ */
/*  Helper: build a JSON-RPC error response                            */
/* ------------------------------------------------------------------ */

static cJSON *build_error_response(int id, int code, const char *message)
{
    cJSON *root  = cJSON_CreateObject();
    cJSON *error = cJSON_CreateObject();

    if (!root || !error) {
        cJSON_Delete(root);
        cJSON_Delete(error);
        return NULL;
    }

    cJSON_AddNumberToObject(root, "id",  id);
    cJSON_AddStringToObject(root, "src", s_dev_id);

    cJSON_AddNumberToObject(error, "code",    code);
    cJSON_AddStringToObject(error, "message", message);
    cJSON_AddItemToObject(root, "error", error);

    return root;
}

/* ------------------------------------------------------------------ */
/*  Handler: EM.GetStatus                                               */
/* ------------------------------------------------------------------ */

static cJSON *handle_em_get_status(int id, const shelly_data_snapshot_t *snap)
{
    cJSON *root   = cJSON_CreateObject();
    cJSON *result = cJSON_CreateObject();

    if (!root || !result) {
        cJSON_Delete(root);
        cJSON_Delete(result);
        return NULL;
    }

    cJSON_AddNumberToObject(root, "id",  id);
    cJSON_AddStringToObject(root, "src", s_dev_id);

    cJSON_AddNumberToObject(result, "id",       0);
    cJSON_AddNumberToObject(result, "ct_state",  1);

    /* Phase A */
    cJSON_AddNumberToObject(result, "a_act_power",  snap->a_act_power);
    cJSON_AddNumberToObject(result, "a_aprt_power", snap->a_aprt_power);
    cJSON_AddNumberToObject(result, "a_current",    snap->a_current);
    cJSON_AddNumberToObject(result, "a_voltage",    snap->a_voltage);
    cJSON_AddNumberToObject(result, "a_pf",         snap->a_pf);
    cJSON_AddNumberToObject(result, "a_freq",       snap->a_freq);

    /* Phase B */
    cJSON_AddNumberToObject(result, "b_act_power",  snap->b_act_power);
    cJSON_AddNumberToObject(result, "b_aprt_power", snap->b_aprt_power);
    cJSON_AddNumberToObject(result, "b_current",    snap->b_current);
    cJSON_AddNumberToObject(result, "b_voltage",    snap->b_voltage);
    cJSON_AddNumberToObject(result, "b_pf",         snap->b_pf);
    cJSON_AddNumberToObject(result, "b_freq",       snap->b_freq);

    /* Phase C */
    cJSON_AddNumberToObject(result, "c_act_power",  snap->c_act_power);
    cJSON_AddNumberToObject(result, "c_aprt_power", snap->c_aprt_power);
    cJSON_AddNumberToObject(result, "c_current",    snap->c_current);
    cJSON_AddNumberToObject(result, "c_voltage",    snap->c_voltage);
    cJSON_AddNumberToObject(result, "c_pf",         snap->c_pf);
    cJSON_AddNumberToObject(result, "c_freq",       snap->c_freq);

    /* Totals */
    cJSON_AddNumberToObject(result, "total_act_power",  snap->total_act_power);
    cJSON_AddNumberToObject(result, "total_aprt_power", snap->total_aprt_power);
    cJSON_AddNumberToObject(result, "total_current",    snap->total_current);
    cJSON_AddNullToObject(result, "n_current");
    cJSON *calib = cJSON_CreateArray();
    if (calib) cJSON_AddItemToObject(result, "user_calibrated_phase", calib);

    cJSON_AddItemToObject(root, "result", result);
    return root;
}

/* ------------------------------------------------------------------ */
/*  Handler: EM.GetConfig                                               */
/* ------------------------------------------------------------------ */

static cJSON *handle_em_get_config(int id)
{
    cJSON *root   = cJSON_CreateObject();
    cJSON *result = cJSON_CreateObject();
    if (!root || !result) { cJSON_Delete(root); cJSON_Delete(result); return NULL; }

    cJSON_AddNumberToObject(root, "id",  id);
    cJSON_AddStringToObject(root, "src", s_dev_id);

    cJSON_AddNumberToObject(result, "id", 0);
    cJSON_AddNullToObject(result, "name");
    cJSON_AddStringToObject(result, "blink_mode_selector", "all");
    cJSON_AddStringToObject(result, "phase_selector", "all");
    cJSON_AddBoolToObject(result, "monitor_phase_sequence", true);
    cJSON_AddStringToObject(result, "ct_type", "120A");

    cJSON_AddItemToObject(root, "result", result);
    return root;
}

static cJSON *handle_em_get_ct_types(int id)
{
    cJSON *root   = cJSON_CreateObject();
    cJSON *result = cJSON_CreateArray();
    if (!root || !result) { cJSON_Delete(root); cJSON_Delete(result); return NULL; }

    cJSON_AddNumberToObject(root, "id",  id);
    cJSON_AddStringToObject(root, "src", s_dev_id);

    cJSON_AddItemToArray(result, cJSON_CreateString("120A"));
    cJSON_AddItemToArray(result, cJSON_CreateString("400A"));
    cJSON_AddItemToArray(result, cJSON_CreateString("50A"));

    cJSON_AddItemToObject(root, "result", result);
    return root;
}

static cJSON *handle_em_set_config(int id)
{
    cJSON *root   = cJSON_CreateObject();
    cJSON *result = cJSON_CreateObject();
    if (!root || !result) { cJSON_Delete(root); cJSON_Delete(result); return NULL; }

    cJSON_AddNumberToObject(root, "id",  id);
    cJSON_AddStringToObject(root, "src", s_dev_id);

    cJSON_AddBoolToObject(result, "restart_required", false);

    cJSON_AddItemToObject(root, "result", result);
    return root;
}

/* ------------------------------------------------------------------ */
/*  Handler: EMData.GetStatus                                           */
/* ------------------------------------------------------------------ */

static cJSON *handle_emdata_get_status(int id, const shelly_data_snapshot_t *snap)
{
    cJSON *root   = cJSON_CreateObject();
    cJSON *result = cJSON_CreateObject();
    if (!root || !result) { cJSON_Delete(root); cJSON_Delete(result); return NULL; }

    cJSON_AddNumberToObject(root, "id",  id);
    cJSON_AddStringToObject(root, "src", s_dev_id);

    cJSON_AddNumberToObject(result, "id", 0);
    cJSON_AddNumberToObject(result, "a_total_act_energy",     snap->a_total_wh);
    cJSON_AddNumberToObject(result, "a_total_act_ret_energy", snap->a_total_ret_wh);
    cJSON_AddNumberToObject(result, "b_total_act_energy",     snap->b_total_wh);
    cJSON_AddNumberToObject(result, "b_total_act_ret_energy", snap->b_total_ret_wh);
    cJSON_AddNumberToObject(result, "c_total_act_energy",     snap->c_total_wh);
    cJSON_AddNumberToObject(result, "c_total_act_ret_energy", snap->c_total_ret_wh);
    cJSON_AddNumberToObject(result, "total_act",              snap->total_act_wh);
    cJSON_AddNumberToObject(result, "total_act_ret",          snap->total_act_ret_wh);

    cJSON_AddItemToObject(root, "result", result);
    return root;
}

/* ------------------------------------------------------------------ */
/*  Handler: Shelly.GetDeviceInfo                                       */
/* ------------------------------------------------------------------ */

static cJSON *handle_shelly_get_device_info(int id)
{
    cJSON *root   = cJSON_CreateObject();
    cJSON *result = cJSON_CreateObject();

    if (!root || !result) {
        cJSON_Delete(root);
        cJSON_Delete(result);
        return NULL;
    }

    cJSON_AddNumberToObject(root, "id",  id);
    cJSON_AddStringToObject(root, "src", s_dev_id);

    cJSON_AddStringToObject(result, "id",     s_dev_id);
    cJSON_AddStringToObject(result, "mac",    s_mac_str);
    cJSON_AddStringToObject(result, "model",  "SPEM-003CEBEU");
    cJSON_AddNumberToObject(result, "gen",    2);
    cJSON_AddStringToObject(result, "fw_id",  "20240101-120000/v1.4.0-esp32gw");
    cJSON_AddStringToObject(result, "ver",    "1.4.0");
    cJSON_AddStringToObject(result, "app",    "Pro3EM");
    cJSON_AddStringToObject(result, "profile","em");

    cJSON_AddItemToObject(root, "result", result);
    return root;
}

/* ------------------------------------------------------------------ */
/*  Handler: Shelly.GetConfig                                           */
/* ------------------------------------------------------------------ */

static cJSON *handle_shelly_get_config(int id)
{
    cJSON *root   = cJSON_CreateObject();
    cJSON *result = cJSON_CreateObject();
    cJSON *em0    = cJSON_CreateObject();
    cJSON *em     = cJSON_CreateObject();
    if (!root || !result || !em0 || !em) {
        cJSON_Delete(root); cJSON_Delete(result); cJSON_Delete(em0); cJSON_Delete(em);
        return NULL;
    }

    cJSON_AddNumberToObject(root, "id",  id);
    cJSON_AddStringToObject(root, "src", s_dev_id);

    cJSON_AddNumberToObject(em0, "id", 0);
    cJSON_AddNullToObject(em0, "name");
    cJSON_AddStringToObject(em0, "phase_selector", "all");
    cJSON_AddStringToObject(em0, "ct_type", "120A");
    cJSON_AddItemToObject(result, "em:0", em0);

    cJSON_AddNumberToObject(em, "id", 0);
    cJSON_AddStringToObject(em, "phase_selector", "all");
    cJSON_AddStringToObject(em, "ct_type", "120A");
    cJSON_AddItemToObject(result, "em", em);

    cJSON_AddItemToObject(root, "result", result);
    return root;
}

/* ------------------------------------------------------------------ */
/*  Handler: Shelly.GetStatus (combined)                                */
/* ------------------------------------------------------------------ */

static cJSON *handle_shelly_get_status(int id, const shelly_data_snapshot_t *snap)
{
    cJSON *em_res     = handle_em_get_status(id, snap);
    cJSON *emdata_res = handle_emdata_get_status(id, snap);
    if (!em_res || !emdata_res) {
        cJSON_Delete(em_res);
        cJSON_Delete(emdata_res);
        return NULL;
    }

    cJSON *em_obj     = cJSON_DetachItemFromObject(em_res, "result");
    cJSON *emdata_obj = cJSON_DetachItemFromObject(emdata_res, "result");
    cJSON_Delete(em_res);
    cJSON_Delete(emdata_res);

    cJSON *root   = cJSON_CreateObject();
    cJSON *result = cJSON_CreateObject();
    cJSON *sys    = cJSON_CreateObject();
    if (!root || !result || !sys) {
        cJSON_Delete(root); cJSON_Delete(result); cJSON_Delete(sys);
        cJSON_Delete(em_obj); cJSON_Delete(emdata_obj);
        return NULL;
    }

    cJSON_AddNumberToObject(root, "id",  id);
    cJSON_AddStringToObject(root, "src", s_dev_id);

    cJSON_AddItemToObject(result, "em:0", em_obj);
    cJSON_AddItemToObject(result, "emdata:0", emdata_obj);

    cJSON_AddStringToObject(sys, "mac", s_mac_str);
    cJSON_AddBoolToObject(sys, "restart_required", false);
    cJSON_AddNumberToObject(sys, "uptime", (double)(esp_timer_get_time() / 1000000LL));
    cJSON_AddItemToObject(result, "sys", sys);

    cJSON_AddItemToObject(root, "result", result);
    return root;
}

/* ------------------------------------------------------------------ */
/*  Handler: Marstek CT002 / CT003 wire protocol                        */
/* ------------------------------------------------------------------ */

static int handle_ct002_request(const uint8_t *rx, size_t rx_len,
                                uint8_t *tx, size_t tx_max,
                                const shelly_data_snapshot_t *snap)
{
    /* Format: SOH(0x01) STX(0x02) <len> | <meter_dev_type> | <meter_mac> | <ct_type> | <ct_mac> | <phase> | <power> ... ETX(0x03) <checksum> */
    if (rx_len < 12 || rx[0] != 0x01 || rx[1] != 0x02 || rx[rx_len - 3] != 0x03) {
        return -1;
    }

    uint8_t xor_sum = 0;
    for (size_t i = 0; i < rx_len - 2; i++) {
        xor_sum ^= rx[i];
    }
    char expected_cs[3];
    snprintf(expected_cs, sizeof(expected_cs), "%02x", xor_sum);
    char actual_hi = (char)tolower((int)rx[rx_len - 2]);
    char actual_lo = (char)tolower((int)rx[rx_len - 1]);
    if (actual_hi != ' ' && actual_hi != expected_cs[0]) return -1;
    if (actual_lo != expected_cs[1]) return -1;

    /* Extract body between initial separator and ETX */
    const char *start_bar = memchr(rx + 2, '|', rx_len - 5);
    if (!start_bar) return -1;

    char body[256];
    size_t body_len = (size_t)((const uint8_t *)memchr(start_bar, 0x03, rx_len - (start_bar - (const char *)rx)) - (const uint8_t *)start_bar);
    if (body_len == 0 || body_len >= sizeof(body)) return -1;
    memcpy(body, start_bar, body_len);
    body[body_len] = '\0';

    char *tokens[10] = {0};
    int tok_cnt = 0;
    char *p = body + 1; /* skip initial '|' */
    while (p && tok_cnt < 10) {
        tokens[tok_cnt++] = p;
        char *sep = strchr(p, '|');
        if (sep) {
            *sep = '\0';
            p = sep + 1;
        } else {
            break;
        }
    }

    if (tok_cnt < 4) return -1;

    const char *meter_dev_type = tokens[0]; /* e.g. HMG-50 or VNSE3-0 */
    const char *meter_mac      = tokens[1]; /* battery MAC */
    const char *ct_type        = tokens[2]; /* e.g. HME-4, HME-3, TPM2-0 */
    const char *req_ct_mac     = (tok_cnt > 3) ? tokens[3] : "";
    const char *req_phase      = (tok_cnt > 4) ? tokens[4] : "0";

    /*
     * CT MAC behavior (AstraMeter & Marstek firmware):
     * If the battery requests a specific CT MAC (not empty and not 000000000000),
     * echo that CT MAC so the battery accepts it immediately.
     * Otherwise send our own lowercase MAC.
     */
    const char *resp_ct_mac = s_mac_str_lower;
    if (req_ct_mac[0] != '\0' && strcmp(req_ct_mac, "000000000000") != 0) {
        resp_ct_mac = req_ct_mac;
    }

    static uint8_t s_info_idx = 0;
    s_info_idx++;

    int pA = (int)roundf(snap->a_act_power);
    int pB = (int)roundf(snap->b_act_power);
    int pC = (int)roundf(snap->c_act_power);
    int pTot = (int)roundf(snap->total_act_power);

    /*
     * Active reporter counts:
     * When battery is on phase A/B/C/D, set that phase's reporter count to 1.
     * Also mark active if that phase has non-zero power.
     */
    int a_nb = (pA != 0) ? 1 : 0;
    int b_nb = (pB != 0) ? 1 : 0;
    int c_nb = (pC != 0) ? 1 : 0;
    int abc_nb = 0;

    char ph = (char)toupper((int)req_phase[0]);
    if (ph == 'A') a_nb = 1;
    else if (ph == 'B') b_nb = 1;
    else if (ph == 'C') c_nb = 1;
    else if (ph == 'D') abc_nb = 1;

    bool is_28_field = (strcasecmp(ct_type, "HME-3") == 0 || strcasecmp(ct_type, "TPM2-0") == 0);

    char msg[384];
    int msg_len = 0;
    if (is_28_field) {
        /* CT003 (HME-3) and newer CT002 (TPM2-0) carry 4 trailing energy registers in 0.1 Wh */
        uint32_t in_wh_x10  = (uint32_t)(snap->total_act_wh * 10.0);
        uint32_t out_wh_x10 = (uint32_t)(snap->total_act_ret_wh * 10.0);
        msg_len = snprintf(msg, sizeof(msg),
            "|%s|%s|%s|%s|%d|%d|%d|%d|%d|%d|%d|%d|-50|%u|0|0|0|0|0|0|0|0|0|0|%lu|0|%lu|0",
            ct_type[0] ? ct_type : "HME-3",
            resp_ct_mac,
            meter_dev_type,
            meter_mac,
            pA, pB, pC, pTot,
            a_nb, b_nb, c_nb, abc_nb,
            s_info_idx,
            (unsigned long)in_wh_x10,
            (unsigned long)out_wh_x10
        );
    } else {
        /* Standard 24-field CT002 (HME-4) */
        msg_len = snprintf(msg, sizeof(msg),
            "|%s|%s|%s|%s|%d|%d|%d|%d|%d|%d|%d|%d|-50|%u|0|0|0|0|0|0|0|0|0|0",
            ct_type[0] ? ct_type : "HME-4",
            resp_ct_mac,
            meter_dev_type,
            meter_mac,
            pA, pB, pC, pTot,
            a_nb, b_nb, c_nb, abc_nb,
            s_info_idx
        );
    }

    if (msg_len <= 0 || (size_t)msg_len >= sizeof(msg)) return -1;

    int total_len = 0;
    int digit_len = 0;
    for (int d = 1; d <= 4; d++) {
        int t = 1 + 1 + d + msg_len + 1 + 2;
        char dbuf[8];
        int dl = snprintf(dbuf, sizeof(dbuf), "%d", t);
        if (dl == d) {
            total_len = t;
            digit_len = d;
            break;
        }
    }
    if (total_len <= 0 || (size_t)total_len > tx_max) return -1;

    int pos = 0;
    tx[pos++] = 0x01; /* SOH */
    tx[pos++] = 0x02; /* STX */
    pos += snprintf((char *)&tx[pos], digit_len + 1, "%d", total_len);
    memcpy(&tx[pos], msg, msg_len);
    pos += msg_len;
    tx[pos++] = 0x03; /* ETX */

    uint8_t cs = 0;
    for (int i = 0; i < pos; i++) cs ^= tx[i];
    snprintf((char *)&tx[pos], 3, "%02x", cs);
    pos += 2;

    return pos;
}

/* ------------------------------------------------------------------ */
/*  UDP Server Task (Multi-port: 2220, 1010, 12345)                   */
/* ------------------------------------------------------------------ */

static int create_udp_socket(int port)
{
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (s < 0) return -1;

    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in bind_addr = {
        .sin_family      = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port        = htons(port),
    };

    if (bind(s, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        ESP_LOGW(TAG, "bind failed on port %d: errno %d", port, errno);
        close(s);
        return -1;
    }

    ESP_LOGI(TAG, "UDP listening on port %d", port);
    return s;
}

static void shelly_udp_task(void *pvParameters)
{
    (void)pvParameters;

    init_device_identity();

    int socks[3];
    int sock_cnt = 0;

    int s_main = create_udp_socket(g_cfg.shelly_udp_port);
    if (s_main >= 0) socks[sock_cnt++] = s_main;

    if (g_cfg.shelly_udp_port != 1010) {
        int s_1010 = create_udp_socket(1010);
        if (s_1010 >= 0) socks[sock_cnt++] = s_1010;
    }

    int s_ct = create_udp_socket(12345);
    if (s_ct >= 0) socks[sock_cnt++] = s_ct;

    if (sock_cnt == 0) {
        ESP_LOGE(TAG, "Failed to bind any UDP socket");
        vTaskDelete(NULL);
        return;
    }

    char *rx_buf = malloc(RX_BUF_SIZE);
    char *tx_buf = malloc(TX_BUF_SIZE);
    if (!rx_buf || !tx_buf) {
        ESP_LOGE(TAG, "Buffer allocation failed");
        for (int i = 0; i < sock_cnt; i++) close(socks[i]);
        free(rx_buf);
        free(tx_buf);
        vTaskDelete(NULL);
        return;
    }

    for (;;) {
        fd_set rfds;
        FD_ZERO(&rfds);
        int max_fd = -1;
        for (int i = 0; i < sock_cnt; i++) {
            FD_SET(socks[i], &rfds);
            if (socks[i] > max_fd) max_fd = socks[i];
        }

        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        int nready = select(max_fd + 1, &rfds, NULL, NULL, &tv);
        if (nready <= 0) continue;

        for (int i = 0; i < sock_cnt; i++) {
            if (!FD_ISSET(socks[i], &rfds)) continue;
            int csock = socks[i];

            struct sockaddr_in sender_addr;
            socklen_t sender_len = sizeof(sender_addr);
            int received = recvfrom(csock, rx_buf, RX_BUF_SIZE - 1, 0,
                                    (struct sockaddr *)&sender_addr, &sender_len);
            if (received <= 0) continue;
            rx_buf[received] = '\0';

            int64_t now_ms = esp_timer_get_time() / 1000LL;
            char sender_ip[16];
            strncpy(sender_ip, inet_ntoa(sender_addr.sin_addr), sizeof(sender_ip) - 1);
            sender_ip[sizeof(sender_ip) - 1] = '\0';
            uint16_t sender_port = ntohs(sender_addr.sin_port);

            if (DATA_LOCK()) {
                g_data.udp_rx_count++;
                g_data.udp_last_rx_ms = now_ms;
                snprintf(g_data.udp_last_client, sizeof(g_data.udp_last_client), "%s:%u", sender_ip, sender_port);
                DATA_UNLOCK();
            }

            shelly_data_snapshot_t snap;
            bool have_snap = data_store_get_shelly_snapshot(&snap);

            /* 1. Check for Marstek CT002 / CT003 frame (SOH STX) */
            if ((uint8_t)rx_buf[0] == 0x01 && (uint8_t)rx_buf[1] == 0x02) {
                if (DATA_LOCK()) {
                    g_data.udp_ct002_count++;
                    strncpy(g_data.udp_last_proto, "CT002", sizeof(g_data.udp_last_proto) - 1);
                    DATA_UNLOCK();
                }
                if (have_snap && snap.shelly_valid) {
                    int resp_len = handle_ct002_request((const uint8_t *)rx_buf, received,
                                                        (uint8_t *)tx_buf, TX_BUF_SIZE, &snap);
                    if (resp_len > 0) {
                        int sent = sendto(csock, tx_buf, resp_len, 0,
                               (struct sockaddr *)&sender_addr, sender_len);
                        if (sent > 0 && DATA_LOCK()) {
                            g_data.udp_tx_count++;
                            DATA_UNLOCK();
                        }
                        ESP_LOGD(TAG, "Replied CT002 to %s:%u", sender_ip, sender_port);
                    }
                }
                continue;
            }

            /* 2. Shelly Pro 3EM JSON-RPC */
            cJSON *req = cJSON_ParseWithLength(rx_buf, (size_t)received);
            if (!req) continue;

            int req_id = 0;
            cJSON *id_item = cJSON_GetObjectItemCaseSensitive(req, "id");
            if (cJSON_IsNumber(id_item)) req_id = (int)id_item->valuedouble;

            cJSON *method_item = cJSON_GetObjectItemCaseSensitive(req, "method");
            const char *method = cJSON_IsString(method_item) ? method_item->valuestring : "";

            if (DATA_LOCK()) {
                g_data.udp_rpc_count++;
                strncpy(g_data.udp_last_proto, method[0] ? method : "RPC", sizeof(g_data.udp_last_proto) - 1);
                DATA_UNLOCK();
            }

            int64_t age_ms = have_snap ? (now_ms - snap.shelly_last_update_ms) : 999999;
            bool is_stale = (!have_snap || !snap.shelly_valid || age_ms > STALE_THRESHOLD_MS);

            cJSON *response = NULL;

            if (strcmp(method, "EM.GetStatus") == 0) {
                if (!is_stale) response = handle_em_get_status(req_id, &snap);
            } else if (strcmp(method, "EM.GetConfig") == 0) {
                response = handle_em_get_config(req_id);
            } else if (strcmp(method, "EM.GetCTTypes") == 0) {
                response = handle_em_get_ct_types(req_id);
            } else if (strcmp(method, "EM.SetConfig") == 0) {
                response = handle_em_set_config(req_id);
            } else if (strcmp(method, "EMData.GetStatus") == 0) {
                if (!is_stale) response = handle_emdata_get_status(req_id, &snap);
            } else if (strcmp(method, "Shelly.GetStatus") == 0) {
                if (!is_stale) response = handle_shelly_get_status(req_id, &snap);
            } else if (strcmp(method, "Shelly.GetDeviceInfo") == 0) {
                response = handle_shelly_get_device_info(req_id);
            } else if (strcmp(method, "Shelly.GetConfig") == 0) {
                response = handle_shelly_get_config(req_id);
            } else {
                response = build_error_response(req_id, -32601, "Method not found");
            }

            cJSON_Delete(req);
            if (!response) continue;

            char *resp_str = cJSON_PrintUnformatted(response);
            cJSON_Delete(response);
            if (!resp_str) continue;

            size_t resp_len = strlen(resp_str);
            if (resp_len < TX_BUF_SIZE) {
                int sent = sendto(csock, resp_str, (int)resp_len, 0,
                                  (struct sockaddr *)&sender_addr, sender_len);
                if (sent > 0 && DATA_LOCK()) {
                    g_data.udp_tx_count++;
                    DATA_UNLOCK();
                }
            }
            free(resp_str);
        }
    }

    for (int i = 0; i < sock_cnt; i++) close(socks[i]);
    free(rx_buf);
    free(tx_buf);
    vTaskDelete(NULL);
}

/* ------------------------------------------------------------------ */
/*  Public API                                                          */
/* ------------------------------------------------------------------ */

void shelly_udp_server_start(void)
{
    BaseType_t ret = xTaskCreate(
        shelly_udp_task,
        "shelly_udp_task",
        TASK_STACK_BYTES,
        NULL,
        TASK_PRIORITY,
        NULL
    );

    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create shelly_udp_task");
    } else {
        ESP_LOGI(TAG, "shelly_udp_task started (port %d)", g_cfg.shelly_udp_port);
    }
}
