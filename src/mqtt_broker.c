/**
 * @file mqtt_broker.c
 * @brief Lightweight embedded MQTT v3.1.1 Broker for ESP32 Energy Gateway.
 *
 * Runs on g_cfg.mqtt_broker_port (default 1883).
 * Accepts client connections from Shelly 3 EM, ioBroker, Home Assistant, etc.
 * Intercepts Shelly telemetry topics and writes measurements directly to g_data.
 * Forwards published messages to all subscribed clients.
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "lwip/sockets.h"
#include "lwip/netdb.h"

#include "esp_log.h"
#include "esp_timer.h"

#include "nvs_config.h"
#include "data_store.h"
#include "mqtt_broker.h"

static const char *TAG = "mqtt_broker";

#define MAX_MQTT_CLIENTS       4
#define MQTT_MAX_TOPIC_LEN     128
#define MAX_SUBS_PER_CLIENT    8
#define MQTT_RX_BUF_SIZE       1536
#define TASK_STACK_SIZE        6144
#define TASK_PRIORITY          5

/* MQTT Packet Types */
#define MQTT_PKT_CONNECT       1u
#define MQTT_PKT_CONNACK       2u
#define MQTT_PKT_PUBLISH       3u
#define MQTT_PKT_PUBACK        4u
#define MQTT_PKT_SUBSCRIBE     8u
#define MQTT_PKT_SUBACK        9u
#define MQTT_PKT_UNSUBSCRIBE   10u
#define MQTT_PKT_UNSUBACK      11u
#define MQTT_PKT_PINGREQ       12u
#define MQTT_PKT_PINGRESP      13u
#define MQTT_PKT_DISCONNECT    14u

typedef struct {
    char    topic[MQTT_MAX_TOPIC_LEN];
    uint8_t qos;
} sub_filter_t;

typedef struct {
    int          sock;
    bool         connected;
    char         client_id[32];
    int64_t      last_activity_ms;
    sub_filter_t subs[MAX_SUBS_PER_CLIENT];
    int          sub_count;
    uint8_t      rx_buf[MQTT_RX_BUF_SIZE];
    size_t       rx_len;
} client_slot_t;

static client_slot_t s_clients[MAX_MQTT_CLIENTS];
static SemaphoreHandle_t s_broker_mutex = NULL;

/* ════════════════════════════════════════════════════════════════════════════
 * Low-Level Helpers & Sending
 * ════════════════════════════════════════════════════════════════════════════ */

static int send_exact(int sock, const uint8_t *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        int n = send(sock, buf + sent, len - sent, 0);
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

static size_t encode_remaining_length(uint8_t *buf, uint32_t length)
{
    size_t bytes = 0;
    do {
        uint8_t d = (uint8_t)(length % 128u);
        length /= 128u;
        if (length > 0) d |= 0x80u;
        buf[bytes++] = d;
    } while (length > 0);
    return bytes;
}

static int decode_remaining_length(const uint8_t *buf, size_t len, uint32_t *out_val, size_t *out_bytes_used)
{
    uint32_t multiplier = 1;
    uint32_t value = 0;
    size_t i = 0;

    while (i < len) {
        uint8_t encoded_byte = buf[i++];
        value += (encoded_byte & 0x7Fu) * multiplier;
        if ((encoded_byte & 0x80u) == 0) {
            *out_val = value;
            *out_bytes_used = i;
            return 0; /* OK */
        }
        multiplier *= 128u;
        if (multiplier > 128u * 128u * 128u) return -1; /* Malformed */
    }
    return 1; /* Incomplete */
}

static void send_connack(int sock, uint8_t ret_code)
{
    uint8_t pkt[4] = { (MQTT_PKT_CONNACK << 4), 2, 0, ret_code };
    send_exact(sock, pkt, sizeof(pkt));
}

static void send_pingresp(int sock)
{
    uint8_t pkt[2] = { (MQTT_PKT_PINGRESP << 4), 0 };
    send_exact(sock, pkt, sizeof(pkt));
}

static void send_puback(int sock, uint16_t packet_id)
{
    uint8_t pkt[4] = {
        (MQTT_PKT_PUBACK << 4), 2,
        (uint8_t)(packet_id >> 8), (uint8_t)(packet_id & 0xFFu)
    };
    send_exact(sock, pkt, sizeof(pkt));
}

static void send_suback(int sock, uint16_t packet_id, const uint8_t *qos_codes, size_t count)
{
    uint8_t buf[64];
    uint32_t rem_len = 2u + (uint32_t)count;
    buf[0] = (MQTT_PKT_SUBACK << 4);
    size_t len_bytes = encode_remaining_length(&buf[1], rem_len);
    size_t pos = 1 + len_bytes;

    buf[pos++] = (uint8_t)(packet_id >> 8);
    buf[pos++] = (uint8_t)(packet_id & 0xFFu);
    for (size_t i = 0; i < count && pos < sizeof(buf); i++) {
        buf[pos++] = qos_codes[i];
    }
    send_exact(sock, buf, pos);
}

static void send_unsuback(int sock, uint16_t packet_id)
{
    uint8_t pkt[4] = {
        (MQTT_PKT_UNSUBACK << 4), 2,
        (uint8_t)(packet_id >> 8), (uint8_t)(packet_id & 0xFFu)
    };
    send_exact(sock, pkt, sizeof(pkt));
}

/* ════════════════════════════════════════════════════════════════════════════
 * Topic Matching & Message Routing
 * ════════════════════════════════════════════════════════════════════════════ */

static bool topic_filter_matches(const char *filter, const char *topic)
{
    if (!filter || !topic) return false;
    if (strcmp(filter, "#") == 0) return true;
    if (strcmp(filter, topic) == 0) return true;

    /* Simple prefix wildcard matching for "prefix/#" */
    size_t flen = strlen(filter);
    if (flen >= 2 && filter[flen - 2] == '/' && filter[flen - 1] == '#') {
        size_t prefix_len = flen - 2;
        if (strncmp(filter, topic, prefix_len) == 0) {
            if (topic[prefix_len] == '\0' || topic[prefix_len] == '/') return true;
        }
    }
    return false;
}

static void forward_publish(int sender_slot, const char *topic, const uint8_t *payload, size_t payload_len)
{
    uint16_t topic_len = (uint16_t)strlen(topic);
    uint32_t rem_len = 2u + topic_len + (uint32_t)payload_len;

    uint8_t header[10];
    header[0] = (MQTT_PKT_PUBLISH << 4); /* QoS 0, no retain */
    size_t len_bytes = encode_remaining_length(&header[1], rem_len);
    size_t hlen = 1 + len_bytes;

    uint8_t topic_hdr[2] = { (uint8_t)(topic_len >> 8), (uint8_t)(topic_len & 0xFF) };

    for (int i = 0; i < MAX_MQTT_CLIENTS; i++) {
        if (i == sender_slot || s_clients[i].sock < 0 || !s_clients[i].connected) continue;

        bool wants_msg = false;
        for (int s = 0; s < s_clients[i].sub_count; s++) {
            if (topic_filter_matches(s_clients[i].subs[s].topic, topic)) {
                wants_msg = true;
                break;
            }
        }

        if (wants_msg) {
            send_exact(s_clients[i].sock, header, hlen);
            send_exact(s_clients[i].sock, topic_hdr, sizeof(topic_hdr));
            send_exact(s_clients[i].sock, (const uint8_t *)topic, topic_len);
            if (payload_len > 0) {
                send_exact(s_clients[i].sock, payload, payload_len);
            }
        }
    }
}

/* ════════════════════════════════════════════════════════════════════════════
 * Shelly 3 EM Telemetry Parser
 * ════════════════════════════════════════════════════════════════════════════ */

static void handle_shelly_telemetry(const char *topic, const char *payload)
{
    /* Shelly 3 EM publishes topics of the form:
     *   shellies/<device_id>/emeter/<idx>/power
     *   shellies/<device_id>/emeter/<idx>/voltage
     *   shellies/<device_id>/emeter/<idx>/current
     *   shellies/<device_id>/emeter/<idx>/pf
     *   shellies/<device_id>/emeter/<idx>/energy
     *   shellies/<device_id>/emeter/<idx>/returned_energy
     *   shellies/<device_id>/emeter/<idx>/total
     *   shellies/<device_id>/emeter/<idx>/total_returned
     */
    const char *em_str = strstr(topic, "/emeter/");
    if (!em_str) return;

    em_str += 8; /* points to index char: '0', '1', or '2' */
    if (*em_str < '0' || *em_str > '2') return;
    int em_idx = *em_str - '0';

    if (*(em_str + 1) != '/') return;
    const char *metric = em_str + 2;

    float fval = strtof(payload, NULL);
    double dval = strtod(payload, NULL);
    int64_t now_ms = esp_timer_get_time() / 1000LL;

    /* Find which phase corresponds to em_idx according to g_cfg.phase_map */
    int phase = -1;
    for (int p = 0; p < 3; p++) {
        if (g_cfg.phase_map[p] == em_idx) {
            phase = p;
            break;
        }
    }
    if (phase < 0) return;

    if (!DATA_LOCK()) return;

    if (strcmp(metric, "power") == 0) {
        if (phase == 0) g_data.a_act_power = fval;
        else if (phase == 1) g_data.b_act_power = fval;
        else if (phase == 2) g_data.c_act_power = fval;

        g_data.total_act_power = g_data.a_act_power + g_data.b_act_power + g_data.c_act_power;
    }
    else if (strcmp(metric, "voltage") == 0) {
        if (phase == 0) { g_data.a_voltage = fval; g_data.a_aprt_power = g_data.a_voltage * g_data.a_current; }
        else if (phase == 1) { g_data.b_voltage = fval; g_data.b_aprt_power = g_data.b_voltage * g_data.b_current; }
        else if (phase == 2) { g_data.c_voltage = fval; g_data.c_aprt_power = g_data.c_voltage * g_data.c_current; }

        g_data.total_aprt_power = g_data.a_aprt_power + g_data.b_aprt_power + g_data.c_aprt_power;
    }
    else if (strcmp(metric, "current") == 0) {
        if (phase == 0) { g_data.a_current = fval; g_data.a_aprt_power = g_data.a_voltage * g_data.a_current; }
        else if (phase == 1) { g_data.b_current = fval; g_data.b_aprt_power = g_data.b_voltage * g_data.b_current; }
        else if (phase == 2) { g_data.c_current = fval; g_data.c_aprt_power = g_data.c_voltage * g_data.c_current; }

        g_data.total_current = g_data.a_current + g_data.b_current + g_data.c_current;
        g_data.total_aprt_power = g_data.a_aprt_power + g_data.b_aprt_power + g_data.c_aprt_power;
    }
    else if (strcmp(metric, "pf") == 0) {
        if (phase == 0) g_data.a_pf = fval;
        else if (phase == 1) g_data.b_pf = fval;
        else if (phase == 2) g_data.c_pf = fval;
    }
    else if (strcmp(metric, "energy") == 0) {
        /* Shelly Gen1 energy is reported in Watt-minutes */
        double wh = dval / 60.0;
        if (phase == 0) g_data.a_total_wh = wh;
        else if (phase == 1) g_data.b_total_wh = wh;
        else if (phase == 2) g_data.c_total_wh = wh;

        g_data.total_act_wh = g_data.a_total_wh + g_data.b_total_wh + g_data.c_total_wh;
    }
    else if (strcmp(metric, "returned_energy") == 0) {
        double wh = dval / 60.0;
        if (phase == 0) g_data.a_total_ret_wh = wh;
        else if (phase == 1) g_data.b_total_ret_wh = wh;
        else if (phase == 2) g_data.c_total_ret_wh = wh;

        g_data.total_act_ret_wh = g_data.a_total_ret_wh + g_data.b_total_ret_wh + g_data.c_total_ret_wh;
    }
    else if (strcmp(metric, "total") == 0) {
        /* Direct Wh value */
        if (phase == 0) g_data.a_total_wh = dval;
        else if (phase == 1) g_data.b_total_wh = dval;
        else if (phase == 2) g_data.c_total_wh = dval;

        g_data.total_act_wh = g_data.a_total_wh + g_data.b_total_wh + g_data.c_total_wh;
    }
    else if (strcmp(metric, "total_returned") == 0) {
        if (phase == 0) g_data.a_total_ret_wh = dval;
        else if (phase == 1) g_data.b_total_ret_wh = dval;
        else if (phase == 2) g_data.c_total_ret_wh = dval;

        g_data.total_act_ret_wh = g_data.a_total_ret_wh + g_data.b_total_ret_wh + g_data.c_total_ret_wh;
    }

    /* Set default frequency if not set */
    if (g_data.a_freq == 0.0f) g_data.a_freq = 50.0f;
    if (g_data.b_freq == 0.0f) g_data.b_freq = 50.0f;
    if (g_data.c_freq == 0.0f) g_data.c_freq = 50.0f;

    g_data.shelly_valid = true;
    g_data.active_meter_source = METER_SRC_MQTT;
    g_data.shelly_last_update_ms = now_ms;
    g_data.mqtt_last_rx_ms = now_ms;
    g_data.mqtt_rx_msgs++;
    g_data.sh_err[0] = '\0';

    DATA_UNLOCK();
}

/* ════════════════════════════════════════════════════════════════════════════
 * MQTT Packet Handler
 * ════════════════════════════════════════════════════════════════════════════ */

static int process_client_packet(int slot, const uint8_t *pkt, size_t pkt_len)
{
    if (pkt_len < 2) return -1;

    uint8_t pkt_type = pkt[0] >> 4;
    uint8_t flags    = pkt[0] & 0x0Fu;

    uint32_t rem_len = 0;
    size_t   len_bytes = 0;
    if (decode_remaining_length(&pkt[1], pkt_len - 1, &rem_len, &len_bytes) != 0) return -1;

    size_t header_len = 1 + len_bytes;
    const uint8_t *body = pkt + header_len;
    size_t body_len = rem_len;

    int csock = s_clients[slot].sock;
    s_clients[slot].last_activity_ms = esp_timer_get_time() / 1000LL;

    switch (pkt_type) {
    case MQTT_PKT_CONNECT: {
        if (body_len < 10) return -1;
        uint16_t proto_name_len = ((uint16_t)body[0] << 8) | body[1];
        if (proto_name_len > body_len - 2) return -1;

        size_t pos = 2 + proto_name_len;
        if (pos + 4 > body_len) return -1;

        /* Protocol level: body[pos] (4 for 3.1.1) */
        uint8_t conn_flags = body[pos + 1];
        /* Keepalive: pos + 2..3 */
        pos += 4;

        /* Client ID */
        if (pos + 2 > body_len) return -1;
        uint16_t cid_len = ((uint16_t)body[pos] << 8) | body[pos + 1];
        pos += 2;
        if (pos + cid_len > body_len) return -1;

        size_t cpy_len = cid_len < (sizeof(s_clients[slot].client_id) - 1) ? cid_len : (sizeof(s_clients[slot].client_id) - 1);
        memcpy(s_clients[slot].client_id, &body[pos], cpy_len);
        s_clients[slot].client_id[cpy_len] = '\0';
        pos += cid_len;

        /* Will flag: skip will topic & message if set */
        if (conn_flags & 0x04u) {
            if (pos + 2 > body_len) return -1;
            uint16_t wt_len = ((uint16_t)body[pos] << 8) | body[pos + 1];
            pos += 2 + wt_len;
            if (pos + 2 > body_len) return -1;
            uint16_t wm_len = ((uint16_t)body[pos] << 8) | body[pos + 1];
            pos += 2 + wm_len;
        }

        /* Check username / password if configured in NVS */
        bool auth_ok = true;
        char user_in[32] = {0};
        char pass_in[32] = {0};

        if (conn_flags & 0x80u) {
            if (pos + 2 <= body_len) {
                uint16_t ulen = ((uint16_t)body[pos] << 8) | body[pos + 1];
                pos += 2;
                if (pos + ulen <= body_len) {
                    size_t cp = ulen < sizeof(user_in) - 1 ? ulen : sizeof(user_in) - 1;
                    memcpy(user_in, &body[pos], cp);
                    pos += ulen;
                }
            }
        }
        if (conn_flags & 0x40u) {
            if (pos + 2 <= body_len) {
                uint16_t plen = ((uint16_t)body[pos] << 8) | body[pos + 1];
                pos += 2;
                if (pos + plen <= body_len) {
                    size_t cp = plen < sizeof(pass_in) - 1 ? plen : sizeof(pass_in) - 1;
                    memcpy(pass_in, &body[pos], cp);
                    pos += plen;
                }
            }
        }

        if (g_cfg.mqtt_user[0] != '\0') {
            if (strcmp(user_in, g_cfg.mqtt_user) != 0 || strcmp(pass_in, g_cfg.mqtt_pass) != 0) {
                ESP_LOGW(TAG, "Client '%s' rejected: bad username or password", s_clients[slot].client_id);
                send_connack(csock, 4); /* Bad user name or password */
                return -1;
            }
        }

        s_clients[slot].connected = true;
        send_connack(csock, 0); /* Accepted */
        ESP_LOGI(TAG, "Client '%s' connected (slot %d)", s_clients[slot].client_id, slot);

        DATA_LOCK();
        strncpy(g_data.mqtt_last_client, s_clients[slot].client_id, sizeof(g_data.mqtt_last_client) - 1);
        g_data.mqtt_last_client[sizeof(g_data.mqtt_last_client) - 1] = '\0';
        DATA_UNLOCK();
        break;
    }

    case MQTT_PKT_PINGREQ:
        send_pingresp(csock);
        break;

    case MQTT_PKT_DISCONNECT:
        ESP_LOGI(TAG, "Client '%s' disconnected gracefully", s_clients[slot].client_id);
        return -1;

    case MQTT_PKT_SUBSCRIBE: {
        if (body_len < 3) return -1;
        uint16_t packet_id = ((uint16_t)body[0] << 8) | body[1];
        size_t pos = 2;

        uint8_t qos_results[MAX_SUBS_PER_CLIENT];
        size_t count = 0;

        while (pos + 3 <= body_len && count < MAX_SUBS_PER_CLIENT) {
            uint16_t tlen = ((uint16_t)body[pos] << 8) | body[pos + 1];
            pos += 2;
            if (pos + tlen + 1 > body_len) break;

            if (s_clients[slot].sub_count < MAX_SUBS_PER_CLIENT) {
                int sidx = s_clients[slot].sub_count++;
                size_t cpy = tlen < (sizeof(s_clients[slot].subs[sidx].topic) - 1) ? tlen : (sizeof(s_clients[slot].subs[sidx].topic) - 1);
                memcpy(s_clients[slot].subs[sidx].topic, &body[pos], cpy);
                s_clients[slot].subs[sidx].topic[cpy] = '\0';
                pos += tlen;
                uint8_t qos = body[pos++];
                s_clients[slot].subs[sidx].qos = qos;
                qos_results[count++] = (qos > 1) ? 1 : qos;
                ESP_LOGI(TAG, "Client '%s' subscribed to '%s'", s_clients[slot].client_id, s_clients[slot].subs[sidx].topic);
            } else {
                pos += tlen + 1;
                qos_results[count++] = 0x80u; /* Failure */
            }
        }
        send_suback(csock, packet_id, qos_results, count);
        break;
    }

    case MQTT_PKT_UNSUBSCRIBE: {
        if (body_len < 3) return -1;
        uint16_t packet_id = ((uint16_t)body[0] << 8) | body[1];
        size_t pos = 2;

        while (pos + 2 <= body_len) {
            uint16_t tlen = ((uint16_t)body[pos] << 8) | body[pos + 1];
            pos += 2;
            if (pos + tlen > body_len) break;

            char untopic[MQTT_MAX_TOPIC_LEN];
            size_t cpy = tlen < sizeof(untopic) - 1 ? tlen : sizeof(untopic) - 1;
            memcpy(untopic, &body[pos], cpy);
            untopic[cpy] = '\0';
            pos += tlen;

            for (int s = 0; s < s_clients[slot].sub_count; s++) {
                if (strcmp(s_clients[slot].subs[s].topic, untopic) == 0) {
                    s_clients[slot].subs[s] = s_clients[slot].subs[--s_clients[slot].sub_count];
                    break;
                }
            }
        }
        send_unsuback(csock, packet_id);
        break;
    }

    case MQTT_PKT_PUBLISH: {
        uint8_t qos = (flags >> 1) & 0x03u;
        if (body_len < 2) return -1;

        uint16_t topic_len = ((uint16_t)body[0] << 8) | body[1];
        if (body_len < 2u + topic_len) return -1;

        char topic_str[MQTT_MAX_TOPIC_LEN];
        size_t cpy = topic_len < sizeof(topic_str) - 1 ? topic_len : sizeof(topic_str) - 1;
        memcpy(topic_str, &body[2], cpy);
        topic_str[cpy] = '\0';

        size_t pos = 2 + topic_len;
        uint16_t packet_id = 0;
        if (qos > 0) {
            if (body_len < pos + 2) return -1;
            packet_id = ((uint16_t)body[pos] << 8) | body[pos + 1];
            pos += 2;
            send_puback(csock, packet_id);
        }

        size_t payload_len = body_len - pos;
        const uint8_t *payload_bytes = &body[pos];

        char payload_str[128];
        size_t pcpy = payload_len < sizeof(payload_str) - 1 ? payload_len : sizeof(payload_str) - 1;
        memcpy(payload_str, payload_bytes, pcpy);
        payload_str[pcpy] = '\0';

        /* 1. Parse Shelly Telemetry */
        handle_shelly_telemetry(topic_str, payload_str);

        /* 2. Forward to other subscribed clients */
        forward_publish(slot, topic_str, payload_bytes, payload_len);
        break;
    }

    default:
        break;
    }

    return 0;
}

/* ════════════════════════════════════════════════════════════════════════════
 * Main Broker Server Task
 * ════════════════════════════════════════════════════════════════════════════ */

static void mqtt_broker_task(void *pvParameters)
{
    (void)pvParameters;

    if (!g_cfg.mqtt_broker_enabled) {
        ESP_LOGI(TAG, "MQTT broker disabled in config");
        vTaskDelete(NULL);
        return;
    }

    int listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock < 0) {
        ESP_LOGE(TAG, "socket() failed");
        vTaskDelete(NULL);
        return;
    }

    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in server_addr = {
        .sin_family      = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port        = htons(g_cfg.mqtt_broker_port),
    };

    if (bind(listen_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0 ||
        listen(listen_sock, 4) != 0) {
        ESP_LOGE(TAG, "bind/listen on port %u failed", g_cfg.mqtt_broker_port);
        close(listen_sock);
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "MQTT broker listening on port %u (max %d clients)",
             g_cfg.mqtt_broker_port, MAX_MQTT_CLIENTS);

    for (int i = 0; i < MAX_MQTT_CLIENTS; i++) {
        s_clients[i].sock = -1;
        s_clients[i].connected = false;
        s_clients[i].rx_len = 0;
    }

    for (;;) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(listen_sock, &read_fds);
        int max_fd = listen_sock;

        int active_clients = 0;
        for (int i = 0; i < MAX_MQTT_CLIENTS; i++) {
            if (s_clients[i].sock >= 0) {
                FD_SET(s_clients[i].sock, &read_fds);
                if (s_clients[i].sock > max_fd) max_fd = s_clients[i].sock;
                active_clients++;
            }
        }

        DATA_LOCK();
        g_data.mqtt_clients_count = (uint8_t)active_clients;
        DATA_UNLOCK();

        struct timeval tv = { .tv_sec = 0, .tv_usec = 100000u }; /* 100 ms */
        int res = select(max_fd + 1, &read_fds, NULL, NULL, &tv);
        if (res <= 0) continue;

        /* Accept new client */
        if (FD_ISSET(listen_sock, &read_fds)) {
            struct sockaddr_in caddr;
            socklen_t clen = sizeof(caddr);
            int newsock = accept(listen_sock, (struct sockaddr *)&caddr, &clen);
            if (newsock >= 0) {
                int slot = -1;
                for (int i = 0; i < MAX_MQTT_CLIENTS; i++) {
                    if (s_clients[i].sock < 0) { slot = i; break; }
                }

                if (slot < 0) {
                    /* Evict oldest */
                    int64_t oldest = INT64_MAX;
                    int o_slot = 0;
                    for (int i = 0; i < MAX_MQTT_CLIENTS; i++) {
                        if (s_clients[i].last_activity_ms < oldest) {
                            oldest = s_clients[i].last_activity_ms;
                            o_slot = i;
                        }
                    }
                    close(s_clients[o_slot].sock);
                    s_clients[o_slot].sock = -1;
                    slot = o_slot;
                }

                int nodelay = 1;
                setsockopt(newsock, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

                s_clients[slot].sock = newsock;
                s_clients[slot].connected = false;
                s_clients[slot].last_activity_ms = esp_timer_get_time() / 1000LL;
                s_clients[slot].client_id[0] = '\0';
                s_clients[slot].sub_count = 0;
                s_clients[slot].rx_len = 0;
            }
        }

        /* Process client traffic */
        for (int i = 0; i < MAX_MQTT_CLIENTS; i++) {
            if (s_clients[i].sock < 0 || !FD_ISSET(s_clients[i].sock, &read_fds)) continue;

            int csock = s_clients[i].sock;
            uint8_t *buf = s_clients[i].rx_buf;
            size_t *rx_len = &s_clients[i].rx_len;

            int n = recv(csock, buf + *rx_len, MQTT_RX_BUF_SIZE - *rx_len, 0);
            if (n <= 0) {
                /* Connection closed or error */
                close(csock);
                s_clients[i].sock = -1;
                s_clients[i].connected = false;
                s_clients[i].rx_len = 0;
                continue;
            }
            *rx_len += (size_t)n;

            /* Parse all complete MQTT packets currently in buffer */
            while (*rx_len >= 2) {
                uint32_t rem_len = 0;
                size_t len_bytes = 0;
                int drc = decode_remaining_length(&buf[1], *rx_len - 1, &rem_len, &len_bytes);
                if (drc == 1) {
                    /* Incomplete remaining length, wait for more data */
                    break;
                }
                if (drc < 0) {
                    /* Malformed packet */
                    close(csock);
                    s_clients[i].sock = -1;
                    s_clients[i].connected = false;
                    s_clients[i].rx_len = 0;
                    break;
                }

                size_t total_pkt_len = 1 + len_bytes + rem_len;
                if (*rx_len < total_pkt_len) {
                    /* Packet not yet completely received */
                    break;
                }

                /* Process single complete packet */
                int prc = process_client_packet(i, buf, total_pkt_len);
                if (prc != 0) {
                    close(csock);
                    s_clients[i].sock = -1;
                    s_clients[i].connected = false;
                    s_clients[i].rx_len = 0;
                    break;
                }

                /* Slide remaining buffer forward */
                size_t remaining = *rx_len - total_pkt_len;
                if (remaining > 0) {
                    memmove(buf, buf + total_pkt_len, remaining);
                }
                *rx_len = remaining;
            }
        }
    }
}

/* ════════════════════════════════════════════════════════════════════════════
 * Public Entry Point
 * ════════════════════════════════════════════════════════════════════════════ */

void mqtt_broker_start(void)
{
    s_broker_mutex = xSemaphoreCreateMutex();
    xTaskCreate(mqtt_broker_task, "mqtt_broker", TASK_STACK_SIZE, NULL, TASK_PRIORITY, NULL);
    ESP_LOGI(TAG, "MQTT broker task launched (port %u)", g_cfg.mqtt_broker_port);
}
