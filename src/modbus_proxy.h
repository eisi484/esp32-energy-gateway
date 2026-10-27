#pragma once
#include <stdbool.h>
#include <stddef.h>
#include "data_store.h"

/**
 * @brief Start the Modbus TCP caching proxy.
 */
void modbus_proxy_start(void);

/** Maximum simultaneous Modbus TCP client connections */
#define MODBUS_MAX_CLIENTS  4

/**
 * @brief Get JSON array of recent Modbus write attempts (for UI & API).
 * @param buf Output buffer
 * @param max_len Buffer size
 * @return Number of characters written
 */
int modbus_proxy_get_write_log_json(char *buf, size_t max_len);

/**
 * @brief Read DTSU666-H meter telemetry directly from Huawei SDongle or proxy cache.
 * @param out_snap Destination snapshot buffer
 * @return true if valid meter data was read, false otherwise
 */
bool modbus_proxy_read_meter(shelly_data_snapshot_t *out_snap);
