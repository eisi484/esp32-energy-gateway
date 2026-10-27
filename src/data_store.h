#pragma once
#include <stdbool.h>
#include <stdint.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

typedef enum {
    METER_SRC_NONE   = 0,
    METER_SRC_SHELLY = 1,
    METER_SRC_HUAWEI = 2,
} meter_source_t;

/**
 * @brief Thread-safe snapshot of Shelly 3-phase and energy data.
 *        Used to format responses outside of DATA_LOCK().
 */
typedef struct {
    float  a_voltage, a_current, a_act_power, a_aprt_power, a_pf, a_freq;
    float  b_voltage, b_current, b_act_power, b_aprt_power, b_pf, b_freq;
    float  c_voltage, c_current, c_act_power, c_aprt_power, c_pf, c_freq;
    float  total_act_power, total_aprt_power, total_current;

    /* 64-bit energy counters in Wh (avoids 32-bit float truncation after 16.7 MWh) */
    double a_total_wh,     b_total_wh,     c_total_wh;     /* Import (Bezug) */
    double a_total_ret_wh, b_total_ret_wh, c_total_ret_wh; /* Export (Einspeisung) */
    double total_act_wh,   total_act_ret_wh;

    bool           shelly_valid;
    int64_t        shelly_last_update_ms;
    meter_source_t active_meter_source;
} shelly_data_snapshot_t;

typedef struct {
    /* ── Shelly / Grid Meter source data (3 phases) ─────────────────── */
    float  a_voltage, a_current, a_act_power, a_aprt_power, a_pf, a_freq;
    float  b_voltage, b_current, b_act_power, b_aprt_power, b_pf, b_freq;
    float  c_voltage, c_current, c_act_power, c_aprt_power, c_pf, c_freq;
    float  total_act_power, total_aprt_power, total_current;

    double a_total_wh,     b_total_wh,     c_total_wh;
    double a_total_ret_wh, b_total_ret_wh, c_total_ret_wh;
    double total_act_wh,   total_act_ret_wh;

    bool           shelly_valid;
    int64_t        shelly_last_update_ms;
    meter_source_t active_meter_source;
    int64_t        huawei_meter_last_update_ms;
    char           sh_err[64];

    /* ── Modbus Proxy Metrics (populated by modbus_proxy.c) ──────────── */
    bool     mb_upstream_connected;
    int64_t  mb_upstream_last_ms;
    char     mb_upstream_err[64];
    uint8_t  mb_client_count;
    uint32_t mb_cache_hits;
    uint32_t mb_cache_misses;
    uint8_t  mb_blocks_cached;

    /* ── UDP / Marstek / Shelly Emulator Metrics ──────────────────────── */
    uint32_t udp_rx_count;
    uint32_t udp_tx_count;
    uint32_t udp_ct002_count;
    uint32_t udp_rpc_count;
    char     udp_last_client[32];
    char     udp_last_proto[16];
    int64_t  udp_last_rx_ms;

    /* ── System status (for web UI) ──────────────────────────────────── */
    bool    eth_connected;
    char    eth_ip[20];
} gateway_data_t;

/** Global data store, access only under g_data_mutex */
extern gateway_data_t  g_data;
extern SemaphoreHandle_t g_data_mutex;

/** Initialize the data store and create the mutex. Call once in app_main. */
void data_store_init(void);

/** Atomically copy current Shelly data snapshot to caller buffer */
bool data_store_get_shelly_snapshot(shelly_data_snapshot_t *out_snap);

/** Convenience macros for thread-safe access */
#define DATA_LOCK()   (xSemaphoreTake(g_data_mutex, pdMS_TO_TICKS(500)) == pdTRUE)
#define DATA_UNLOCK() xSemaphoreGive(g_data_mutex)
