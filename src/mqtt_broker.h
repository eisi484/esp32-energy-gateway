#pragma once
#include <stdbool.h>

/**
 * @brief Start the embedded MQTT v3.1.1 broker task.
 *
 * Listens on g_cfg.mqtt_broker_port (default 1883).
 * Accepts client connections from Shelly 3 EM, ioBroker, Home Assistant, etc.
 * Parses Shelly telemetry topics and updates g_data in real-time (< 10 ms).
 * Forwards published messages to subscribed clients.
 */
void mqtt_broker_start(void);
