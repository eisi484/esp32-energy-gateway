#pragma once

/**
 * @brief Start the Shelly 3 Pro EM UDP emulator task.
 *
 * Binds to UDP port g_cfg.shelly_udp_port (default 2220).
 * Handles JSON-RPC 2.0 requests from Marstek Venus E:
 *   - Method "EM.GetStatus"  → returns live 3-phase data from g_data
 *   - Method "Shelly.GetDeviceInfo" → returns device identification
 *   - Unknown methods        → returns JSON-RPC error response
 *
 * Reads data from g_data under mutex.
 * Sends UDP response back to the source IP/port.
 */
void shelly_udp_server_start(void);
