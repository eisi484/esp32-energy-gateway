#pragma once

/**
 * @brief Start the Shelly 3 EM polling task.
 *
 * Polls GET http://<g_cfg.shelly_ip>/status every g_cfg.shelly_poll_ms.
 * Parses emeters[0..2] from JSON and writes into g_data (under mutex).
 * Uses g_cfg.phase_map[] to assign emeter indices to phases A/B/C.
 *
 * The task does nothing if g_cfg.shelly_ip is "0.0.0.0" or empty.
 */
void shelly_client_start(void);
