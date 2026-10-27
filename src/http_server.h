#pragma once
#include "esp_err.h"

/**
 * @brief Start the combined HTTP server on port 80.
 *
 * Routes provided:
 *
 *  Web Configuration Portal:
 *    GET  /            → redirect to /config
 *    GET  /config      → HTML configuration form (Tabs: Status, Config, OTA)
 *    POST /config      → save form data to NVS, schedule reboot (Auth & CSRF protected)
 *    POST /update      → Web OTA firmware flash (Auth & CSRF protected)
 *    GET  /api/status  → JSON: eth/shelly/modbus/heap status for live-update widget
 *    POST /api/reset   → factory reset (erase NVS, reboot)
 *
 *  Shelly 3 Pro EM API (Gen2 / SPEM-003CEBEU):
 *    GET  /shelly                  → device identification (model, mac, gen=2)
 *    GET  /rpc/Shelly.GetDeviceInfo → same as /shelly
 *    GET  /rpc/Shelly.GetConfig    → minimal config stub
 *    GET  /rpc/Shelly.GetStatus    → combined em:0, emdata:0, sys status (HTTP 503 if stale)
 *    GET  /rpc/EM.GetStatus        → live 3-phase data from g_data (HTTP 503 if stale)
 *    GET  /rpc/EMData.GetStatus    → 64-bit energy totals from g_data (HTTP 503 if stale)
 *    POST /rpc                     → JSON-RPC 2.0 dispatcher
 *
 * @return ESP_OK on success
 */
esp_err_t http_server_start(void);
