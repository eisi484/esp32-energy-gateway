/**
 * @file modbus_proxy.c
 * @brief Hardened transparent Modbus TCP caching proxy for ESP32 Energy Gateway.
 *
 * Features:
 *  - Single persistent upstream connection to Huawei SDongle with mutex serialization
 *  - 32-slot static memory-bounded TTL cache (LRU eviction)
 *  - Stale-while-revalidate for minimal downstream latency (EVCC / ioBroker)
 *  - Request coalescing (parallel clients share pending upstream fetch)
 *  - Write-policy: disabled by default, strict Huawei storage allowlist when enabled
 *  - Full overlapping cache invalidation on successful writes
 *  - Stream-based MBAP framing & TCP keepalive on client connections
 *  - Priority & stack sizing hardened for 24/7 industrial use
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
#include "freertos/event_groups.h"

#include "lwip/sockets.h"
#include "lwip/netdb.h"

#include "esp_log.h"
#include "esp_timer.h"

#include "nvs_config.h"
#include "data_store.h"
#include "modbus_proxy.h"

/* ── Logging tag ─────────────────────────────────────────────────────────── */
static const char *TAG = "mb_proxy";

/* ── Modbus Function Codes ───────────────────────────────────────────────── */
#define MB_FC_READ_HOLDING    0x03u
#define MB_FC_READ_INPUT      0x04u
#define MB_FC_WRITE_SINGLE    0x06u
#define MB_FC_WRITE_MULTIPLE  0x10u

/* ── Modbus Exceptions ───────────────────────────────────────────────────── */
#define MB_EXC_ILLEGAL_FN     0x01u
#define MB_EXC_ILLEGAL_ADDR   0x02u
#define MB_EXC_ILLEGAL_VAL    0x03u
#define MB_EXC_DEV_FAILURE    0x04u
#define MB_EXC_SLAVE_BUSY     0x06u
#define MB_EXC_GATEWAY_TARGET 0x0Bu

/* ── Protocol & Buffer Limits ────────────────────────────────────────────── */
#define MBAP_HEADER_LEN       6u
#define MAX_REGS_PER_READ     125u
#define MAX_CACHE_ENTRIES     32u
#define MAX_PREPOLL_ENTRIES   8u
#define UPSTREAM_PACING_MS    150LL
#define UPSTREAM_TIMEOUT_MS   5000

/* Coalescing event bits */
#define COALESCE_BIT_OK       BIT0
#define COALESCE_BIT_ERR      BIT1

/* ── Cache Entry Definition ──────────────────────────────────────────────── */
typedef struct {
    uint8_t  unit_id;
    uint8_t  fc;
    uint16_t start_addr;
    uint16_t count;
    uint16_t regs[MAX_REGS_PER_READ];
    int64_t  last_update_ms;
    int64_t  last_access_ms;
    bool     valid;
    bool     fetching;
    EventGroupHandle_t wait_event;
} cache_entry_t;

static cache_entry_t   s_cache[MAX_CACHE_ENTRIES];
static SemaphoreHandle_t s_cache_mutex    = NULL;
static SemaphoreHandle_t s_upstream_mutex = NULL;
static int             s_upstream_sock   = -1;
static int64_t         s_last_upstream_ms = 0;
static uint16_t        s_upstream_tid     = 0;

/* ── Allowlist definition for Huawei Storage Write Registers ────────────── */
/*
 * Huawei SUN2000 Storage Control Registers (Huawei Modbus Definition V3/V5):
 *  47075..47076 : Maximum charging power (uint32, W)
 *  47077..47078 : Maximum discharging power (uint32, W)
 *  47081        : Charging cutoff capacity SOC (uint16, 0.1%)
 *  47082        : Discharging cutoff capacity SOC (uint16, 0.1%)
 *  47086        : Storage working mode (uint16, 0..6)
 *  47087        : Charge from grid function (uint16, 0=disable, 1=enable)
 *  47088        : Grid charge cutoff capacity SOC (uint16, 0.1%)
 */
static bool is_write_range_allowed(uint16_t start, uint16_t count)
{
    if (count == 0 || count > 32) return false;
    uint16_t end = start + count - 1;

    /* Range 1: 47075..47078 (Charge & Discharge power limits) */
    if (start >= 47075 && end <= 47078) return true;

    /* Range 2: 47081..47082 (Cutoff SOC limits) */
    if (start >= 47081 && end <= 47082) return true;

    /* Range 3: 47086..47088 (Working mode, Grid charge enable, Grid charge cutoff) */
    if (start >= 47086 && end <= 47088) return true;

    return false;
}

/**
 * @brief Determine effective TTL and Max-Age for a register block.
 * Any block that overlaps dynamic power/control registers:
 *  - Inverter active power & currents: 32064..32100 (Wirkleistung 32080)
 *  - Grid meter active power & currents: 37100..37130 (Wirkleistung 37113)
 *  - Battery instantaneous power: 37000..37010
 *  - Battery ESS telemetry: 37760..37780
 * gets a short TTL of 1500 ms and a Max-Age of 4000 ms, ensuring EVCC and control
 * loops never act on stale data.
 * Other blocks (counters, serial numbers, grid info) use the user-configured values.
 */
static inline void get_effective_cache_policy(uint16_t start, uint16_t count,
                                              int64_t *out_ttl_ms, int64_t *out_max_age_ms)
{
    uint16_t end = start + count - 1;
    bool is_fast = (start <= 32100 && end >= 32064) ||
                   (start <= 37138 && end >= 37100) ||
                   (start <= 37010 && end >= 37000) ||
                   (start <= 37780 && end >= 37760);
    if (is_fast) {
        *out_ttl_ms = 1500LL;      /* 1.5s TTL for fast control loops */
        *out_max_age_ms = 4000LL;  /* max 4.0s before forcing upstream sync */
    } else {
        *out_ttl_ms = (int64_t)g_cfg.modbus_cache_ms;
        *out_max_age_ms = (int64_t)g_cfg.modbus_max_age_ms;
    }
}

/* ── Write Log Ring Buffer (for UI and API inspection) ───────────────────── */
#define WRITE_LOG_SIZE 10

typedef struct {
    int64_t  timestamp_s;
    uint8_t  unit_id;
    uint8_t  fc;
    uint16_t start_addr;
    uint16_t count;
    uint32_t val_preview;
    bool     allowed;
    uint8_t  exc_code;
} write_log_entry_t;

static write_log_entry_t s_write_log[WRITE_LOG_SIZE];
static int s_write_log_head = 0;
static int s_write_log_count = 0;
static SemaphoreHandle_t s_write_log_mutex = NULL;

static void record_write_log(uint8_t uid, uint8_t fc, uint16_t start, uint16_t count,
                             uint32_t val, bool allowed, uint8_t exc)
{
    if (!s_write_log_mutex) s_write_log_mutex = xSemaphoreCreateMutex();
    if (xSemaphoreTake(s_write_log_mutex, pdMS_TO_TICKS(50)) == pdTRUE) {
        int idx = s_write_log_head;
        s_write_log[idx].timestamp_s = esp_timer_get_time() / 1000000LL;
        s_write_log[idx].unit_id = uid;
        s_write_log[idx].fc = fc;
        s_write_log[idx].start_addr = start;
        s_write_log[idx].count = count;
        s_write_log[idx].val_preview = val;
        s_write_log[idx].allowed = allowed;
        s_write_log[idx].exc_code = exc;
        s_write_log_head = (s_write_log_head + 1) % WRITE_LOG_SIZE;
        if (s_write_log_count < WRITE_LOG_SIZE) s_write_log_count++;
        xSemaphoreGive(s_write_log_mutex);
    }
}

int modbus_proxy_get_write_log_json(char *buf, size_t max_len)
{
    if (!s_write_log_mutex) s_write_log_mutex = xSemaphoreCreateMutex();
    if (!buf || max_len < 3) return 0;

    int written = snprintf(buf, max_len, "[");
    if (xSemaphoreTake(s_write_log_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
        for (int i = 0; i < s_write_log_count; i++) {
            int idx = (s_write_log_head - s_write_log_count + i + WRITE_LOG_SIZE) % WRITE_LOG_SIZE;
            int n = snprintf(buf + written, max_len - written,
                "%s{\"t\":%lld,\"uid\":%u,\"fc\":%u,\"addr\":%u,\"cnt\":%u,\"val\":%lu,\"ok\":%s,\"exc\":%u}",
                (i > 0) ? "," : "",
                (long long)s_write_log[idx].timestamp_s,
                s_write_log[idx].unit_id,
                s_write_log[idx].fc,
                s_write_log[idx].start_addr,
                s_write_log[idx].count,
                (unsigned long)s_write_log[idx].val_preview,
                s_write_log[idx].allowed ? "true" : "false",
                s_write_log[idx].exc_code
            );
            if (n < 0 || (size_t)(written + n) >= max_len - 2) break;
            written += n;
        }
        xSemaphoreGive(s_write_log_mutex);
    }
    written += snprintf(buf + written, max_len - written, "]");
    return written;
}

/* ════════════════════════════════════════════════════════════════════════════
 * Low-level Socket I/O
 * ════════════════════════════════════════════════════════════════════════════ */

static int recv_exact(int sock, uint8_t *buf, size_t len)
{
    size_t received = 0;
    while (received < len) {
        int n = recv(sock, buf + received, len - received, 0);
        if (n <= 0) return -1;
        received += (size_t)n;
    }
    return 0;
}

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

static void send_mbap_response(int sock, uint16_t tid, uint8_t uid,
                               const uint8_t *pdu, uint16_t pdu_len)
{
    uint16_t length_field = 1u + pdu_len;
    uint8_t  frame[MBAP_HEADER_LEN + 1u + 256u];

    if (pdu_len > 256u) return;

    frame[0] = (uint8_t)(tid >> 8);
    frame[1] = (uint8_t)(tid & 0xFFu);
    frame[2] = 0x00u;
    frame[3] = 0x00u;
    frame[4] = (uint8_t)(length_field >> 8);
    frame[5] = (uint8_t)(length_field & 0xFFu);
    frame[6] = uid;

    memcpy(&frame[7], pdu, pdu_len);
    send_exact(sock, frame, MBAP_HEADER_LEN + 1u + pdu_len);
}

static void send_modbus_exception(int sock, uint16_t tid, uint8_t uid,
                                  uint8_t fc, uint8_t exc_code)
{
    uint8_t pdu[2];
    pdu[0] = fc | 0x80u;
    pdu[1] = exc_code;
    send_mbap_response(sock, tid, uid, pdu, sizeof(pdu));
}

/* ════════════════════════════════════════════════════════════════════════════
 * Upstream Connection & Pacing
 * ════════════════════════════════════════════════════════════════════════════ */

static int64_t s_last_connect_fail_ms = 0;

static int upstream_connect(void)
{
    if (s_upstream_sock >= 0) return 0;
    if (g_cfg.huawei_ip[0] == '\0' || strcmp(g_cfg.huawei_ip, "0.0.0.0") == 0) {
        return -1;
    }

    int64_t now_ms = esp_timer_get_time() / 1000LL;
    /* Backoff: wait 5000 ms before retrying after a failed connect to avoid task thrashing */
    if (now_ms - s_last_connect_fail_ms < 5000LL) {
        return -1;
    }

    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) return -1;

    /* Set non-blocking to prevent blocking during TCP SYN handshake */
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags >= 0) fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in dest = {
        .sin_family = AF_INET,
        .sin_port   = htons(g_cfg.huawei_port),
    };
    if (inet_pton(AF_INET, g_cfg.huawei_ip, &dest.sin_addr) != 1) {
        close(sock);
        s_last_connect_fail_ms = now_ms;
        return -1;
    }

    int res = connect(sock, (struct sockaddr *)&dest, sizeof(dest));
    if (res < 0 && errno == EINPROGRESS) {
        fd_set fdset;
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);
        struct timeval conn_tv = { .tv_sec = 4, .tv_usec = 0 }; /* 4.0s connect timeout */
        if (select(sock + 1, NULL, &fdset, NULL, &conn_tv) > 0) {
            int so_error = 0;
            socklen_t optlen = sizeof(so_error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &optlen);
            if (so_error != 0) {
                ESP_LOGW(TAG, "connect failed: so_error=%d", so_error);
                DATA_LOCK();
                snprintf(g_data.mb_upstream_err, sizeof(g_data.mb_upstream_err), "so_error=%d", so_error);
                DATA_UNLOCK();
                close(sock);
                s_last_connect_fail_ms = now_ms;
                return -1;
            }
        } else {
            ESP_LOGW(TAG, "connect timeout (4s) to %s:%u", g_cfg.huawei_ip, g_cfg.huawei_port);
            DATA_LOCK();
            snprintf(g_data.mb_upstream_err, sizeof(g_data.mb_upstream_err), "timeout 4s");
            DATA_UNLOCK();
            close(sock);
            s_last_connect_fail_ms = now_ms;
            return -1;
        }
    } else if (res < 0) {
        ESP_LOGW(TAG, "connect error errno=%d", errno);
        DATA_LOCK();
        snprintf(g_data.mb_upstream_err, sizeof(g_data.mb_upstream_err), "errno=%d", errno);
        DATA_UNLOCK();
        close(sock);
        s_last_connect_fail_ms = now_ms;
        return -1;
    }

    /* Restore blocking mode and apply SO_RCVTIMEO / SO_SNDTIMEO */
    if (flags >= 0) fcntl(sock, F_SETFL, flags);

    struct timeval tv = { .tv_sec = UPSTREAM_TIMEOUT_MS / 1000,
                          .tv_usec = (UPSTREAM_TIMEOUT_MS % 1000) * 1000 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    int nodelay = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

    s_upstream_sock = sock;
    DATA_LOCK();
    g_data.mb_upstream_connected = true;
    snprintf(g_data.mb_upstream_err, sizeof(g_data.mb_upstream_err), "OK");
    DATA_UNLOCK();
    ESP_LOGI(TAG, "Connected to Huawei SDongle %s:%u", g_cfg.huawei_ip, g_cfg.huawei_port);

    /* SDongle stabilization pause */
    vTaskDelay(pdMS_TO_TICKS(500));
    return 0;
}

static void upstream_disconnect(const char *reason)
{
    if (s_upstream_sock >= 0) {
        close(s_upstream_sock);
        s_upstream_sock = -1;
        DATA_LOCK();
        g_data.mb_upstream_connected = false;
        if (reason) {
            snprintf(g_data.mb_upstream_err, sizeof(g_data.mb_upstream_err), "%s", reason);
        }
        DATA_UNLOCK();
        ESP_LOGW(TAG, "Disconnected from SDongle: %s", reason ? reason : "unspecified");
    }
}

/**
 * @brief Execute a raw Modbus request over the serialized upstream link.
 * Caller MUST hold s_upstream_mutex.
 */
static int upstream_transact(uint8_t uid, const uint8_t *req_pdu, size_t req_pdu_len,
                             uint8_t *resp_pdu, size_t *resp_pdu_len, size_t max_resp_len)
{
    if (upstream_connect() != 0) return -1;

    /* Enforce pacing on the SDongle RS485 bus */
    int64_t now_ms = esp_timer_get_time() / 1000LL;
    int64_t elapsed = now_ms - s_last_upstream_ms;
    if (elapsed < UPSTREAM_PACING_MS) {
        vTaskDelay(pdMS_TO_TICKS(UPSTREAM_PACING_MS - elapsed));
    }

    uint16_t tid = ++s_upstream_tid;
    uint16_t length_field = 1u + (uint16_t)req_pdu_len;
    uint8_t  frame[MBAP_HEADER_LEN + 1u + 256u];

    frame[0] = (uint8_t)(tid >> 8);
    frame[1] = (uint8_t)(tid & 0xFFu);
    frame[2] = 0x00u;
    frame[3] = 0x00u;
    frame[4] = (uint8_t)(length_field >> 8);
    frame[5] = (uint8_t)(length_field & 0xFFu);
    frame[6] = uid;
    memcpy(&frame[7], req_pdu, req_pdu_len);

    if (send_exact(s_upstream_sock, frame, MBAP_HEADER_LEN + 1u + req_pdu_len) != 0) {
        upstream_disconnect("send failed");
        return -1;
    }

    /* Read MBAP */
    uint8_t mbap[MBAP_HEADER_LEN];
    if (recv_exact(s_upstream_sock, mbap, MBAP_HEADER_LEN) != 0) {
        upstream_disconnect("recv mbap timeout");
        return -1;
    }

    uint16_t resp_len = ((uint16_t)mbap[4] << 8) | mbap[5];
    if (resp_len < 2u || resp_len > 260u) {
        upstream_disconnect("invalid resp_len");
        return -1;
    }

    uint8_t body[260];
    if (recv_exact(s_upstream_sock, body, resp_len) != 0) {
        upstream_disconnect("recv body timeout");
        return -1;
    }

    s_last_upstream_ms = esp_timer_get_time() / 1000LL;
    DATA_LOCK();
    g_data.mb_upstream_last_ms = s_last_upstream_ms;
    DATA_UNLOCK();

    /* body[0] is UID, body[1..] is PDU */
    size_t pdu_len = resp_len - 1u;
    if (pdu_len > max_resp_len) pdu_len = max_resp_len;
    memcpy(resp_pdu, &body[1], pdu_len);
    *resp_pdu_len = pdu_len;

    return 0;
}


/* ════════════════════════════════════════════════════════════════════════════
 * Cache Management & Overlapping Invalidation
 * ════════════════════════════════════════════════════════════════════════════ */

static void cache_init(void)
{
    s_cache_mutex = xSemaphoreCreateMutex();
    s_upstream_mutex = xSemaphoreCreateMutex();

    for (int i = 0; i < MAX_CACHE_ENTRIES; i++) {
        memset(&s_cache[i], 0, sizeof(cache_entry_t));
        s_cache[i].wait_event = xEventGroupCreate();
    }
}

/**
 * @brief Invalidate all cache entries that overlap with write range [start, start + count - 1]
 */
static void cache_invalidate_overlap(uint8_t uid, uint16_t start, uint16_t count)
{
    if (xSemaphoreTake(s_cache_mutex, pdMS_TO_TICKS(200)) != pdTRUE) return;

    uint16_t wr_end = start + count - 1;
    for (int i = 0; i < MAX_CACHE_ENTRIES; i++) {
        if (!s_cache[i].valid) continue;
        if (s_cache[i].unit_id != uid) continue;

        uint16_t ce_start = s_cache[i].start_addr;
        uint16_t ce_end   = ce_start + s_cache[i].count - 1;

        /* Overlap condition: max(ce_start, start) <= min(ce_end, wr_end) */
        uint16_t ov_start = (ce_start > start) ? ce_start : start;
        uint16_t ov_end   = (ce_end < wr_end)  ? ce_end   : wr_end;

        if (ov_start <= ov_end) {
            s_cache[i].valid = false;
            ESP_LOGI(TAG, "Cache slot %d invalidated due to write overlap [%u..%u]",
                     i, start, wr_end);
        }
    }

    xSemaphoreGive(s_cache_mutex);
}

/**
 * @brief Find matching slot or allocate slot with LRU eviction.
 */
static int cache_find_or_alloc_slot(uint8_t uid, uint8_t fc, uint16_t start, uint16_t count)
{
    int empty_slot = -1;
    int lru_slot   = 0;
    int64_t oldest_time = INT64_MAX;

    for (int i = 0; i < MAX_CACHE_ENTRIES; i++) {
        if (s_cache[i].valid &&
            s_cache[i].unit_id == uid &&
            s_cache[i].fc == fc &&
            s_cache[i].start_addr == start &&
            s_cache[i].count == count) {
            return i; /* Exact match */
        }
        if (!s_cache[i].valid && !s_cache[i].fetching && empty_slot < 0) {
            empty_slot = i;
        }
        if (s_cache[i].last_access_ms < oldest_time && !s_cache[i].fetching) {
            oldest_time = s_cache[i].last_access_ms;
            lru_slot = i;
        }
    }

    if (empty_slot >= 0) return empty_slot;
    return lru_slot;
}

/**
 * @brief Fetch a register block from SDongle and store into cache slot.
 * Caller MUST hold s_upstream_mutex.
 */
static int fetch_block_upstream(uint8_t uid, uint8_t fc, uint16_t start, uint16_t count,
                                uint16_t *out_regs)
{
    uint8_t req_pdu[5];
    req_pdu[0] = fc;
    req_pdu[1] = (uint8_t)(start >> 8);
    req_pdu[2] = (uint8_t)(start & 0xFF);
    req_pdu[3] = (uint8_t)(count >> 8);
    req_pdu[4] = (uint8_t)(count & 0xFF);

    uint8_t resp_pdu[260];
    size_t  resp_pdu_len = 0;

    int rc = upstream_transact(uid, req_pdu, sizeof(req_pdu), resp_pdu,
                               &resp_pdu_len, sizeof(resp_pdu));
    if (rc != 0 || resp_pdu_len < 3) return -1;

    /* Check Modbus exception */
    if (resp_pdu[0] & 0x80u) {
        ESP_LOGW(TAG, "Upstream exception: FC=0x%02X code=0x%02X", resp_pdu[0], resp_pdu[1]);
        DATA_LOCK();
        snprintf(g_data.mb_upstream_err, sizeof(g_data.mb_upstream_err), "Dongle Exc 0x%02X", resp_pdu[1]);
        DATA_UNLOCK();
        return resp_pdu[1];
    }

    if (resp_pdu[0] != fc) return -1;
    uint8_t byte_count = resp_pdu[1];
    if (byte_count != (uint8_t)(count * 2u) || resp_pdu_len < (size_t)(2u + byte_count)) {
        return -1;
    }

    memcpy(out_regs, &resp_pdu[2], byte_count);
    return 0;
}

/**
 * @brief Read registers from cache (stale-while-revalidate + coalescing).
 */
static int cache_get_or_fetch(uint8_t uid, uint8_t fc, uint16_t start, uint16_t count,
                              uint8_t *out_bytes)
{
    if (count == 0 || count > MAX_REGS_PER_READ) return MB_EXC_ILLEGAL_ADDR;

    int64_t now_ms = esp_timer_get_time() / 1000LL;
    int slot = -1;
    bool is_fetching = false;
    EventGroupHandle_t wait_evt = NULL;

    if (xSemaphoreTake(s_cache_mutex, pdMS_TO_TICKS(200)) == pdTRUE) {
        slot = cache_find_or_alloc_slot(uid, fc, start, count);
        s_cache[slot].last_access_ms = now_ms;

        if (s_cache[slot].valid &&
            s_cache[slot].unit_id == uid &&
            s_cache[slot].fc == fc &&
            s_cache[slot].start_addr == start &&
            s_cache[slot].count == count) {

            int64_t age = now_ms - s_cache[slot].last_update_ms;
            int64_t eff_ttl = 0, eff_max_age = 0;
            get_effective_cache_policy(start, count, &eff_ttl, &eff_max_age);

            /* Fresh Hit */
            if (age <= eff_ttl) {
                memcpy(out_bytes, s_cache[slot].regs, (size_t)count * 2u);
                xSemaphoreGive(s_cache_mutex);
                DATA_LOCK();
                g_data.mb_cache_hits++;
                DATA_UNLOCK();
                return 0;
            }

            /* Stale-while-revalidate Hit: return current data, refresh in background */
            if (age <= eff_max_age) {
                memcpy(out_bytes, s_cache[slot].regs, (size_t)count * 2u);
                DATA_LOCK();
                g_data.mb_cache_hits++;
                DATA_UNLOCK();

                if (!s_cache[slot].fetching) {
                    s_cache[slot].fetching = true;
                    xEventGroupClearBits(s_cache[slot].wait_event, COALESCE_BIT_OK | COALESCE_BIT_ERR);
                    xSemaphoreGive(s_cache_mutex);

                    /* Try non-blocking background refresh */
                    if (xSemaphoreTake(s_upstream_mutex, 0) == pdTRUE) {
                        uint16_t tmp_regs[MAX_REGS_PER_READ];
                        int ret = fetch_block_upstream(uid, fc, start, count, tmp_regs);
                        if (ret == 0 && xSemaphoreTake(s_cache_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
                            memcpy(s_cache[slot].regs, tmp_regs, (size_t)count * 2u);
                            s_cache[slot].last_update_ms = esp_timer_get_time() / 1000LL;
                            s_cache[slot].valid = true;
                            xSemaphoreGive(s_cache_mutex);
                        }
                        xSemaphoreGive(s_upstream_mutex);
                    }

                    if (xSemaphoreTake(s_cache_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
                        s_cache[slot].fetching = false;
                        xSemaphoreGive(s_cache_mutex);
                    }
                } else {
                    xSemaphoreGive(s_cache_mutex);
                }
                return 0;
            }
        }

        /* Hard Miss or age > max_age_ms */
        DATA_LOCK();
        g_data.mb_cache_misses++;
        DATA_UNLOCK();

        if (s_cache[slot].fetching) {
            is_fetching = true;
            wait_evt = s_cache[slot].wait_event;
        } else {
            s_cache[slot].unit_id = uid;
            s_cache[slot].fc = fc;
            s_cache[slot].start_addr = start;
            s_cache[slot].count = count;
            s_cache[slot].fetching = true;
            xEventGroupClearBits(s_cache[slot].wait_event, COALESCE_BIT_OK | COALESCE_BIT_ERR);
        }
        xSemaphoreGive(s_cache_mutex);
    } else {
        return MB_EXC_SLAVE_BUSY;
    }

    /* Coalescing: another client is already fetching this exact block */
    if (is_fetching && wait_evt) {
        EventBits_t bits = xEventGroupWaitBits(wait_evt, COALESCE_BIT_OK | COALESCE_BIT_ERR,
                                               pdFALSE, pdFALSE, pdMS_TO_TICKS(5000));
        if (bits & COALESCE_BIT_OK) {
            if (xSemaphoreTake(s_cache_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
                memcpy(out_bytes, s_cache[slot].regs, (size_t)count * 2u);
                xSemaphoreGive(s_cache_mutex);
                return 0;
            }
        }
        return MB_EXC_GATEWAY_TARGET;
    }

    /* We are the primary fetcher */
    if (xSemaphoreTake(s_upstream_mutex, pdMS_TO_TICKS(5000)) != pdTRUE) {
        if (xSemaphoreTake(s_cache_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
            s_cache[slot].fetching = false;
            xEventGroupSetBits(s_cache[slot].wait_event, COALESCE_BIT_ERR);
            xSemaphoreGive(s_cache_mutex);
        }
        return MB_EXC_SLAVE_BUSY;
    }

    uint16_t fetched_regs[MAX_REGS_PER_READ];
    int rc = fetch_block_upstream(uid, fc, start, count, fetched_regs);
    xSemaphoreGive(s_upstream_mutex);

    if (xSemaphoreTake(s_cache_mutex, pdMS_TO_TICKS(200)) == pdTRUE) {
        s_cache[slot].fetching = false;
        if (rc == 0) {
            memcpy(s_cache[slot].regs, fetched_regs, (size_t)count * 2u);
            s_cache[slot].last_update_ms = esp_timer_get_time() / 1000LL;
            s_cache[slot].valid = true;
            xEventGroupSetBits(s_cache[slot].wait_event, COALESCE_BIT_OK);
            memcpy(out_bytes, fetched_regs, (size_t)count * 2u);
            xSemaphoreGive(s_cache_mutex);
            return 0;
        } else {
            xEventGroupSetBits(s_cache[slot].wait_event, COALESCE_BIT_ERR);
            xSemaphoreGive(s_cache_mutex);
            return (rc > 0) ? rc : MB_EXC_GATEWAY_TARGET;
        }
    }

    return MB_EXC_SLAVE_BUSY;
}

/* ════════════════════════════════════════════════════════════════════════════
 * Modbus Server Task (Downstream)
 * ════════════════════════════════════════════════════════════════════════════ */

static void modbus_server_task(void *arg)
{
    (void)arg;

    int listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock < 0) {
        ESP_LOGE(TAG, "server: socket() failed");
        vTaskDelete(NULL);
        return;
    }

    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in server_addr = {
        .sin_family      = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port        = htons(g_cfg.modbus_proxy_port),
    };

    if (bind(listen_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0 ||
        listen(listen_sock, 4) != 0) {
        ESP_LOGE(TAG, "server: bind/listen failed");
        close(listen_sock);
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "Modbus proxy listening on port %u (max %d clients)",
             g_cfg.modbus_proxy_port, MODBUS_MAX_CLIENTS);

    int clients[MODBUS_MAX_CLIENTS];
    int64_t client_activity[MODBUS_MAX_CLIENTS];
    for (int i = 0; i < MODBUS_MAX_CLIENTS; i++) {
        clients[i] = -1;
        client_activity[i] = 0;
    }

    for (;;) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(listen_sock, &read_fds);
        int max_fd = listen_sock;

        for (int i = 0; i < MODBUS_MAX_CLIENTS; i++) {
            if (clients[i] >= 0) {
                FD_SET(clients[i], &read_fds);
                if (clients[i] > max_fd) max_fd = clients[i];
            }
        }

        struct timeval timeout = { .tv_sec = 0, .tv_usec = 100000u }; /* 100 ms */
        int nready = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);
        if (nready <= 0) continue;

        /* Accept new client */
        if (FD_ISSET(listen_sock, &read_fds)) {
            struct sockaddr_in client_addr;
            socklen_t len = sizeof(client_addr);
            int new_sock = accept(listen_sock, (struct sockaddr *)&client_addr, &len);
            if (new_sock >= 0) {
                int slot = -1;
                for (int i = 0; i < MODBUS_MAX_CLIENTS; i++) {
                    if (clients[i] < 0) { slot = i; break; }
                }

                /* If all slots full, evict the oldest inactive client */
                if (slot < 0) {
                    int64_t oldest = INT64_MAX;
                    int evict_idx = 0;
                    for (int i = 0; i < MODBUS_MAX_CLIENTS; i++) {
                        if (client_activity[i] < oldest) {
                            oldest = client_activity[i];
                            evict_idx = i;
                        }
                    }
                    ESP_LOGW(TAG, "Evicting inactive client slot %d for new connection", evict_idx);
                    close(clients[evict_idx]);
                    clients[evict_idx] = -1;
                    slot = evict_idx;
                }

                int keepalive = 1, keepidle = 10, keepintvl = 3, keepcnt = 3;
                setsockopt(new_sock, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
                setsockopt(new_sock, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
                setsockopt(new_sock, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl));
                setsockopt(new_sock, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt));

                clients[slot] = new_sock;
                client_activity[slot] = esp_timer_get_time() / 1000LL;

                DATA_LOCK();
                g_data.mb_client_count++;
                DATA_UNLOCK();
            }
        }

        /* Service clients */
        for (int i = 0; i < MODBUS_MAX_CLIENTS; i++) {
            if (clients[i] < 0 || !FD_ISSET(clients[i], &read_fds)) continue;

            int csock = clients[i];
            client_activity[i] = esp_timer_get_time() / 1000LL;

            /* Read MBAP header (6 bytes) */
            uint8_t mbap[MBAP_HEADER_LEN];
            if (recv_exact(csock, mbap, MBAP_HEADER_LEN) != 0) {
                close(csock);
                clients[i] = -1;
                DATA_LOCK();
                if (g_data.mb_client_count > 0) g_data.mb_client_count--;
                DATA_UNLOCK();
                continue;
            }

            uint16_t tid     = ((uint16_t)mbap[0] << 8) | mbap[1];
            uint16_t pid     = ((uint16_t)mbap[2] << 8) | mbap[3];
            uint16_t pdu_len = ((uint16_t)mbap[4] << 8) | mbap[5];

            if (pid != 0x0000u || pdu_len < 2u || pdu_len > 256u) {
                close(csock);
                clients[i] = -1;
                DATA_LOCK();
                if (g_data.mb_client_count > 0) g_data.mb_client_count--;
                DATA_UNLOCK();
                continue;
            }

            uint8_t body[256];
            if (recv_exact(csock, body, pdu_len) != 0) {
                close(csock);
                clients[i] = -1;
                DATA_LOCK();
                if (g_data.mb_client_count > 0) g_data.mb_client_count--;
                DATA_UNLOCK();
                continue;
            }

            uint8_t uid = body[0];
            uint8_t fc  = body[1];

            /* --- READ (FC 03 / FC 04) --- */
            if (fc == MB_FC_READ_HOLDING || fc == MB_FC_READ_INPUT) {
                if (pdu_len < 5) {
                    send_modbus_exception(csock, tid, uid, fc, MB_EXC_ILLEGAL_ADDR);
                    continue;
                }
                uint16_t start = ((uint16_t)body[2] << 8) | body[3];
                uint16_t count = ((uint16_t)body[4] << 8) | body[5];

                uint8_t reg_bytes[MAX_REGS_PER_READ * 2u];
                int exc = cache_get_or_fetch(uid, fc, start, count, reg_bytes);
                if (exc != 0) {
                    send_modbus_exception(csock, tid, uid, fc, (uint8_t)exc);
                } else {
                    uint16_t byte_count = count * 2u;
                    uint8_t  resp_pdu[2u + MAX_REGS_PER_READ * 2u];
                    resp_pdu[0] = fc;
                    resp_pdu[1] = (uint8_t)byte_count;
                    memcpy(&resp_pdu[2], reg_bytes, byte_count);
                    send_mbap_response(csock, tid, uid, resp_pdu, 2u + byte_count);
                }
            }
            /* --- WRITE (FC 06 / FC 16) --- */
            else if (fc == MB_FC_WRITE_SINGLE || fc == MB_FC_WRITE_MULTIPLE) {
                uint16_t start = ((uint16_t)body[2] << 8) | body[3];
                uint16_t count = (fc == MB_FC_WRITE_SINGLE) ? 1 : (((uint16_t)body[4] << 8) | body[5]);

                static int64_t s_last_write_ms = 0;
                int64_t now_w_ms = esp_timer_get_time() / 1000LL;

                /* 1. Extract value preview & validate function code rules */
                uint32_t val_preview = 0;
                bool val_ok = true;

                if (fc == MB_FC_WRITE_SINGLE) {
                    /* FC06 on 32-bit registers (47075..47078) is an illegal partial write */
                    if (start >= 47075 && start <= 47078) {
                        ESP_LOGW(TAG, "FC06 rejected on 32-bit register %u (requires FC16 with count=2)", start);
                        record_write_log(uid, fc, start, 1, 0, false, MB_EXC_ILLEGAL_FN);
                        send_modbus_exception(csock, tid, uid, fc, MB_EXC_ILLEGAL_FN);
                        continue;
                    }
                    val_preview = ((uint32_t)body[4] << 8) | body[5];
                    if (start == 47086 && val_preview > 6u) val_ok = false;
                    if ((start == 47081 || start == 47082 || start == 47088) && val_preview > 1000u) val_ok = false;
                    if (start == 47087 && val_preview > 1u) val_ok = false;
                } else if (fc == MB_FC_WRITE_MULTIPLE && pdu_len >= 7) {
                    uint8_t byte_cnt = body[6];
                    if ((start == 47075 || start == 47077) && count == 2 && byte_cnt == 4) {
                        val_preview = ((uint32_t)body[7] << 24) | ((uint32_t)body[8] << 16) |
                                      ((uint32_t)body[9] << 8)  | body[10];
                        if (val_preview > 50000u) val_ok = false; /* Max 50 kW charging/discharging */
                    } else if (count == 1 && byte_cnt == 2) {
                        val_preview = ((uint32_t)body[7] << 8) | body[8];
                        if (start == 47086 && val_preview > 6u) val_ok = false;
                        if ((start == 47081 || start == 47082 || start == 47088) && val_preview > 1000u) val_ok = false;
                        if (start == 47087 && val_preview > 1u) val_ok = false;
                    } else if ((start == 47075 || start == 47077) && count != 2) {
                        /* 32-bit register pair must be written as exactly 2 registers */
                        val_ok = false;
                    }
                }

                if (!val_ok) {
                    ESP_LOGW(TAG, "Write rejected: Value %lu out of valid range for reg %u",
                             (unsigned long)val_preview, start);
                    record_write_log(uid, fc, start, count, val_preview, false, MB_EXC_ILLEGAL_VAL);
                    send_modbus_exception(csock, tid, uid, fc, MB_EXC_ILLEGAL_VAL);
                    continue;
                }

                /* 2. Rate limit: at least 2000 ms between writes to prevent wear */
                if (now_w_ms - s_last_write_ms < 2000LL) {
                    ESP_LOGW(TAG, "Write rate-limited (min 2000 ms interval)");
                    record_write_log(uid, fc, start, count, val_preview, false, MB_EXC_SLAVE_BUSY);
                    send_modbus_exception(csock, tid, uid, fc, MB_EXC_SLAVE_BUSY);
                    continue;
                }

                /* 3. Check configuration policy */
                if (g_cfg.modbus_allow_writes == 0) {
                    ESP_LOGW(TAG, "Write blocked (modbus_allow_writes = 0: Deaktiviert)");
                    record_write_log(uid, fc, start, count, val_preview, false, MB_EXC_ILLEGAL_FN);
                    send_modbus_exception(csock, tid, uid, fc, MB_EXC_ILLEGAL_FN);
                    continue;
                }

                bool allowed = is_write_range_allowed(start, count);

                if (g_cfg.modbus_allow_writes == 1) {
                    /* Beobachtungsmodus (Observation Mode): Log & record, but never execute */
                    ESP_LOGW(TAG, "[BEOBACHTUNGSMODUS] Schreibversuch abgefangen: Unit=%u FC=0x%02X Start=%u Count=%u Val=%lu -> %s",
                             uid, fc, start, count, (unsigned long)val_preview, allowed ? "IN ALLOWLIST" : "NICHT IN ALLOWLIST");
                    record_write_log(uid, fc, start, count, val_preview, allowed, MB_EXC_ILLEGAL_FN);
                    send_modbus_exception(csock, tid, uid, fc, MB_EXC_ILLEGAL_FN);
                    continue;
                }

                /* modbus_allow_writes == 2 (Aktiviert) */
                if (!allowed) {
                    ESP_LOGW(TAG, "Write rejected: Addr %u Count %u not in allowlist", start, count);
                    record_write_log(uid, fc, start, count, val_preview, false, MB_EXC_ILLEGAL_ADDR);
                    send_modbus_exception(csock, tid, uid, fc, MB_EXC_ILLEGAL_ADDR);
                    continue;
                }

                /* Allowed write: pass through to SDongle */
                if (xSemaphoreTake(s_upstream_mutex, pdMS_TO_TICKS(5000)) != pdTRUE) {
                    record_write_log(uid, fc, start, count, val_preview, false, MB_EXC_SLAVE_BUSY);
                    send_modbus_exception(csock, tid, uid, fc, MB_EXC_SLAVE_BUSY);
                    continue;
                }

                uint8_t resp_pdu[64];
                size_t  resp_pdu_len = 0;
                int rc = upstream_transact(uid, &body[1], pdu_len - 1, resp_pdu,
                                           &resp_pdu_len, sizeof(resp_pdu));
                xSemaphoreGive(s_upstream_mutex);

                if (rc == 0 && resp_pdu_len > 0) {
                    s_last_write_ms = esp_timer_get_time() / 1000LL;
                    record_write_log(uid, fc, start, count, val_preview, true, 0);
                    /* Invalidate overlapping read caches */
                    cache_invalidate_overlap(uid, start, count);
                    send_mbap_response(csock, tid, uid, resp_pdu, (uint16_t)resp_pdu_len);
                } else {
                    record_write_log(uid, fc, start, count, val_preview, false, MB_EXC_GATEWAY_TARGET);
                    send_modbus_exception(csock, tid, uid, fc, MB_EXC_GATEWAY_TARGET);
                }
            }
            /* --- UNKNOWN FUNCTION CODE --- */
            else {
                send_modbus_exception(csock, tid, uid, fc, MB_EXC_ILLEGAL_FN);
            }
        }
    }
}

/* ════════════════════════════════════════════════════════════════════════════
 * Public Entry Point
 * ════════════════════════════════════════════════════════════════════════════ */

void modbus_proxy_start(void)
{
    cache_init();

    xTaskCreate(modbus_server_task, "mb_server", 6144u, NULL, 5u, NULL);
    ESP_LOGI(TAG, "Modbus proxy started (TTL=%ums, MaxAge=%ums, Writes=%s)",
             g_cfg.modbus_cache_ms, g_cfg.modbus_max_age_ms,
             g_cfg.modbus_allow_writes ? "ALLOWLIST" : "DISABLED");
}

/* ════════════════════════════════════════════════════════════════════════════
 * Huawei DTSU666-H Meter Reader (Fallback for Shelly)
 * ════════════════════════════════════════════════════════════════════════════ */

static inline int32_t unpack_i32(const uint8_t *b) {
    return (int32_t)(((uint32_t)b[0] << 24) |
                     ((uint32_t)b[1] << 16) |
                     ((uint32_t)b[2] << 8)  |
                      (uint32_t)b[3]);
}

static inline uint32_t unpack_u32(const uint8_t *b) {
    return (((uint32_t)b[0] << 24) |
            ((uint32_t)b[1] << 16) |
            ((uint32_t)b[2] << 8)  |
             (uint32_t)b[3]);
}

static inline int16_t unpack_i16(const uint8_t *b) {
    return (int16_t)(((uint16_t)b[0] << 8) | (uint16_t)b[1]);
}

static inline uint16_t unpack_u16(const uint8_t *b) {
    return (uint16_t)(((uint16_t)b[0] << 8) | (uint16_t)b[1]);
}

bool modbus_proxy_read_meter(shelly_data_snapshot_t *out_snap)
{
    if (!out_snap) return false;
    if (g_cfg.huawei_ip[0] == '\0' || strcmp(g_cfg.huawei_ip, "0.0.0.0") == 0) return false;

    uint8_t b[38 * 2]; /* 76 bytes for 38 registers 37100..37137 */
    int exc = cache_get_or_fetch(g_cfg.huawei_slave_id, MB_FC_READ_HOLDING, 37100, 38, b);
    if (exc != 0) {
        return false;
    }

    uint16_t meter_status = unpack_u16(&b[0]);
    if (meter_status != 1) {
        ESP_LOGD(TAG, "Huawei DTSU666 status not normal: %u", meter_status);
        return false;
    }

    float ua = (float)unpack_i32(&b[2]) * 0.1f;
    float ub = (float)unpack_i32(&b[6]) * 0.1f;
    float uc = (float)unpack_i32(&b[10]) * 0.1f;

    /* Plausibility check on voltages */
    if (ua < 50.0f && ub < 50.0f && uc < 50.0f) {
        return false;
    }

    float ia = fabsf((float)unpack_i32(&b[14]) * 0.01f);
    float ib = fabsf((float)unpack_i32(&b[18]) * 0.01f);
    float ic = fabsf((float)unpack_i32(&b[22]) * 0.01f);

    /* 37113: Total Active Power (int32, W).
     * Huawei sign: >0 is feed-in (export), <0 is grid import (consumption).
     * Shelly / Marstek sign: >0 is grid import (consumption), <0 is feed-in.
     * Invert sign so positive means house consumption/import. */
    int32_t raw_p_tot = unpack_i32(&b[26]);
    float total_act_power = -(float)raw_p_tot;

    float pf = (float)unpack_i16(&b[34]) * 0.001f;
    if (pf == 0.0f) pf = 1.0f;

    float freq = (float)unpack_i16(&b[36]) * 0.01f;
    if (freq < 45.0f || freq > 65.0f) freq = 50.0f;

    double pos_wh = (double)unpack_u32(&b[38]) * 10.0; /* 0.01 kWh = 10 Wh */
    double rev_wh = (double)unpack_u32(&b[42]) * 10.0;

    /* Phase active powers: 37132, 37134, 37136 (offsets 64, 68, 72) */
    int32_t raw_pa = unpack_i32(&b[64]);
    int32_t raw_pb = unpack_i32(&b[68]);
    int32_t raw_pc = unpack_i32(&b[72]);

    float pa = -(float)raw_pa;
    float pb = -(float)raw_pb;
    float pc = -(float)raw_pc;

    if (raw_pa == 0 && raw_pb == 0 && raw_pc == 0 && raw_p_tot != 0) {
        float s_tot = (ua * ia) + (ub * ib) + (uc * ic);
        if (s_tot > 1.0f) {
            pa = total_act_power * ((ua * ia) / s_tot);
            pb = total_act_power * ((ub * ib) / s_tot);
            pc = total_act_power * ((uc * ic) / s_tot);
        } else {
            pa = total_act_power / 3.0f;
            pb = total_act_power / 3.0f;
            pc = total_act_power / 3.0f;
        }
    }

    float aprt_a = ua * ia;
    float aprt_b = ub * ib;
    float aprt_c = uc * ic;

    out_snap->a_voltage    = ua;
    out_snap->a_current    = ia;
    out_snap->a_act_power  = pa;
    out_snap->a_aprt_power = aprt_a;
    out_snap->a_pf         = pf;
    out_snap->a_freq       = freq;
    out_snap->a_total_wh   = pos_wh / 3.0;
    out_snap->a_total_ret_wh = rev_wh / 3.0;

    out_snap->b_voltage    = ub;
    out_snap->b_current    = ib;
    out_snap->b_act_power  = pb;
    out_snap->b_aprt_power = aprt_b;
    out_snap->b_pf         = pf;
    out_snap->b_freq       = freq;
    out_snap->b_total_wh   = pos_wh / 3.0;
    out_snap->b_total_ret_wh = rev_wh / 3.0;

    out_snap->c_voltage    = uc;
    out_snap->c_current    = ic;
    out_snap->c_act_power  = pc;
    out_snap->c_aprt_power = aprt_c;
    out_snap->c_pf         = pf;
    out_snap->c_freq       = freq;
    out_snap->c_total_wh   = pos_wh / 3.0;
    out_snap->c_total_ret_wh = rev_wh / 3.0;

    out_snap->total_act_power  = total_act_power;
    out_snap->total_aprt_power = aprt_a + aprt_b + aprt_c;
    out_snap->total_current    = ia + ib + ic;
    out_snap->total_act_wh     = pos_wh;
    out_snap->total_act_ret_wh = rev_wh;

    out_snap->shelly_valid          = true;
    out_snap->shelly_last_update_ms = esp_timer_get_time() / 1000LL;
    out_snap->active_meter_source   = METER_SRC_HUAWEI;

    DATA_LOCK();
    g_data.huawei_meter_last_update_ms = out_snap->shelly_last_update_ms;
    DATA_UNLOCK();

    return true;
}
