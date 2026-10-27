#include <string.h>
#include "data_store.h"

gateway_data_t    g_data;
SemaphoreHandle_t g_data_mutex;

void data_store_init(void) {
    memset(&g_data, 0, sizeof(g_data));
    g_data_mutex = xSemaphoreCreateMutex();
    configASSERT(g_data_mutex != NULL);
}

bool data_store_get_shelly_snapshot(shelly_data_snapshot_t *out_snap) {
    if (!out_snap) return false;
    if (!DATA_LOCK()) return false;

    out_snap->a_voltage        = g_data.a_voltage;
    out_snap->a_current        = g_data.a_current;
    out_snap->a_act_power      = g_data.a_act_power;
    out_snap->a_aprt_power     = g_data.a_aprt_power;
    out_snap->a_pf             = g_data.a_pf;
    out_snap->a_freq           = g_data.a_freq;

    out_snap->b_voltage        = g_data.b_voltage;
    out_snap->b_current        = g_data.b_current;
    out_snap->b_act_power      = g_data.b_act_power;
    out_snap->b_aprt_power     = g_data.b_aprt_power;
    out_snap->b_pf             = g_data.b_pf;
    out_snap->b_freq           = g_data.b_freq;

    out_snap->c_voltage        = g_data.c_voltage;
    out_snap->c_current        = g_data.c_current;
    out_snap->c_act_power      = g_data.c_act_power;
    out_snap->c_aprt_power     = g_data.c_aprt_power;
    out_snap->c_pf             = g_data.c_pf;
    out_snap->c_freq           = g_data.c_freq;

    out_snap->total_act_power  = g_data.total_act_power;
    out_snap->total_aprt_power = g_data.total_aprt_power;
    out_snap->total_current    = g_data.total_current;

    out_snap->a_total_wh       = g_data.a_total_wh;
    out_snap->b_total_wh       = g_data.b_total_wh;
    out_snap->c_total_wh       = g_data.c_total_wh;

    out_snap->a_total_ret_wh   = g_data.a_total_ret_wh;
    out_snap->b_total_ret_wh   = g_data.b_total_ret_wh;
    out_snap->c_total_ret_wh   = g_data.c_total_ret_wh;

    out_snap->total_act_wh     = g_data.total_act_wh;
    out_snap->total_act_ret_wh = g_data.total_act_ret_wh;

    out_snap->shelly_valid     = g_data.shelly_valid;
    out_snap->shelly_last_update_ms = g_data.shelly_last_update_ms;
    out_snap->active_meter_source   = g_data.active_meter_source;

    DATA_UNLOCK();
    return true;
}
