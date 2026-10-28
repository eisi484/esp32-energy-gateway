/**
 * @file http_server.c
 * @brief Hardened HTTP server for ESP32 Energy Gateway.
 *
 * Routes:
 *   GET  /                       → 302 redirect to /config
 *   GET  /config                 → Configuration HTML portal (Tabs: Status, Config, OTA)
 *   POST /config                 → Save config (JSON, CSRF + Auth protected)
 *   POST /update                 → Web OTA firmware upload (CSRF + Auth protected)
 *   GET  /api/status             → JSON live status (Uptime, Free Heap, Modbus, Shelly)
 *   POST /api/reset              → Factory reset (CSRF + Auth protected)
 *   GET  /shelly                 → Shelly device-info JSON
 *   GET  /rpc/Shelly.GetDeviceInfo → same as /shelly
 *   GET  /rpc/Shelly.GetConfig   → minimal config stub JSON
 *   GET  /rpc/Shelly.GetStatus   → combined Gen2 telemetry (HTTP 503 if stale)
 *   GET  /rpc/EM.GetStatus       → live 3-phase measurements (HTTP 503 if stale)
 *   GET  /rpc/EMData.GetStatus   → 64-bit double energy counters (HTTP 503 if stale)
 *   POST /rpc                    → JSON-RPC dispatcher
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "freertos/FreeRTOS.h"
#include "freertos/timers.h"

#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_timer.h"
#include "esp_netif.h"
#include "esp_ota_ops.h"
#include "esp_app_format.h"
#include "esp_system.h"
#include "esp_random.h"
#include "nvs_flash.h"
#include "mbedtls/base64.h"
#include "mbedtls/sha256.h"

#include "cJSON.h"
#include "data_store.h"
#include "nvs_config.h"
#include "modbus_proxy.h"
#include "http_server.h"

#define TAG "http_server"
#define STALE_THRESHOLD_MS 4000

/* ------------------------------------------------------------------ */
/*  Reboot timer                                                        */
/* ------------------------------------------------------------------ */

static void reboot_timer_cb(TimerHandle_t xTimer)
{
    (void)xTimer;
    esp_restart();
}

static void schedule_reboot(uint32_t delay_ms)
{
    TimerHandle_t t = xTimerCreate("reboot_timer", pdMS_TO_TICKS(delay_ms),
                                   pdFALSE, NULL, reboot_timer_cb);
    if (t) xTimerStart(t, 0);
}

/* ------------------------------------------------------------------ */
/*  Identity Helper                                                     */
/* ------------------------------------------------------------------ */

static void get_device_identity(char *mac_str, size_t mac_len, char *dev_id, size_t id_len)
{
    uint8_t mac[6];
    if (esp_read_mac(mac, ESP_MAC_ETH) == ESP_OK) {
        snprintf(mac_str, mac_len, "%02X%02X%02X%02X%02X%02X",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        snprintf(dev_id, id_len, "shellypro3em-%02x%02x%02x%02x%02x%02x",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    } else {
        strncpy(mac_str, "AABBCCDDEEFF", mac_len);
        strncpy(dev_id, "shellypro3em-esp32", id_len);
    }
}

/* ------------------------------------------------------------------ */
/*  Security: Basic Auth & CSRF Check                                   */
/* ------------------------------------------------------------------ */

static bool check_host_header(httpd_req_t *req)
{
    char host[64];
    if (httpd_req_get_hdr_value_str(req, "Host", host, sizeof(host)) != ESP_OK) {
        return false;
    }
    char *colon = strchr(host, ':');
    if (colon) *colon = '\0';

    if (strcmp(host, "127.0.0.1") == 0 || strcmp(host, "localhost") == 0 ||
        strcmp(host, "esp32-energy-gateway") == 0 || strcmp(host, "esp32-energy-gateway.local") == 0) {
        return true;
    }

    char cur_ip[20];
    DATA_LOCK();
    strncpy(cur_ip, g_data.eth_ip, sizeof(cur_ip) - 1);
    cur_ip[sizeof(cur_ip) - 1] = '\0';
    DATA_UNLOCK();

    if (cur_ip[0] != '\0' && strcmp(host, cur_ip) == 0) {
        return true;
    }
    return false;
}

static bool check_auth(httpd_req_t *req)
{
    /* If no password configured, first-time setup mode: allow access */
    if (g_cfg.admin_pw_hash[0] == '\0' && g_cfg.admin_password[0] == '\0') {
        return true;
    }

    char auth_hdr[128];
    if (httpd_req_get_hdr_value_str(req, "Authorization", auth_hdr, sizeof(auth_hdr)) != ESP_OK) {
        return false;
    }

    if (strncmp(auth_hdr, "Basic ", 6) != 0) {
        return false;
    }

    const char *b64 = auth_hdr + 6;
    unsigned char decoded[96];
    size_t out_len = 0;
    if (mbedtls_base64_decode(decoded, sizeof(decoded) - 1, &out_len,
                              (const unsigned char *)b64, strlen(b64)) != 0) {
        return false;
    }
    decoded[out_len] = '\0';

    if (strncmp((char *)decoded, "admin:", 6) != 0) {
        return false;
    }
    const char *pw = (char *)decoded + 6;

    /* 1. Salted SHA-256 verification (constant-time) */
    if (g_cfg.admin_pw_hash[0] != '\0' && g_cfg.admin_pw_salt[0] != '\0') {
        char to_hash[128];
        snprintf(to_hash, sizeof(to_hash), "%s%s", g_cfg.admin_pw_salt, pw);

        uint8_t hash_out[32];
        mbedtls_sha256((const unsigned char *)to_hash, strlen(to_hash), hash_out, 0);

        char computed_hex[65];
        for (int i = 0; i < 32; i++) snprintf(&computed_hex[i * 2], 3, "%02x", hash_out[i]);
        computed_hex[64] = '\0';

        int diff = 0;
        for (int i = 0; i < 64; i++) {
            diff |= (computed_hex[i] ^ g_cfg.admin_pw_hash[i]);
        }
        return (diff == 0);
    }

    /* 2. Fallback to legacy password */
    if (g_cfg.admin_password[0] != '\0') {
        return (strcmp(pw, g_cfg.admin_password) == 0);
    }

    return false;
}

static esp_err_t send_unauthorized(httpd_req_t *req)
{
    httpd_resp_set_status(req, "401 Unauthorized");
    httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"ESP32 Energy Gateway\"");
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_send(req, "401 Unauthorized", HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

static bool check_csrf(httpd_req_t *req)
{
    if (!check_host_header(req)) {
        return false;
    }
    char hdr[64];
    /* Check custom header X-Requested-With */
    if (httpd_req_get_hdr_value_str(req, "X-Requested-With", hdr, sizeof(hdr)) != ESP_OK) {
        return false;
    }
    return true;
}

static esp_err_t send_forbidden(httpd_req_t *req, const char *reason)
{
    httpd_resp_set_status(req, "403 Forbidden");
    httpd_resp_set_type(req, "application/json");
    char buf[128];
    snprintf(buf, sizeof(buf), "{\"error\":\"Forbidden\",\"reason\":\"%s\"}", reason);
    httpd_resp_send(req, buf, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

/* ------------------------------------------------------------------ */
/*  Web Portal HTML (with Tabs for Status, Config, and OTA)            */
/* ------------------------------------------------------------------ */

static void html_escape(const char *src, char *dst, size_t dst_len)
{
    size_t d = 0;
    while (*src && d + 6 < dst_len) {
        switch (*src) {
            case '&': memcpy(&dst[d], "&amp;", 5); d += 5; break;
            case '<': memcpy(&dst[d], "&lt;", 4);  d += 4; break;
            case '>': memcpy(&dst[d], "&gt;", 4);  d += 4; break;
            case '"': memcpy(&dst[d], "&quot;", 6); d += 6; break;
            default:  dst[d++] = *src; break;
        }
        src++;
    }
    dst[d] = '\0';
}

static const char HTML_STATIC_HEAD[] =
"<!DOCTYPE html><html lang=\"de\"><head><meta charset=\"utf-8\">"
"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
"<title>ESP32 Energy Gateway</title><style>"
"body{font-family:system-ui,-apple-system,sans-serif;max-width:680px;margin:0 auto;padding:12px;background:#f8f9fa;color:#212529}"
"h1{font-size:1.4em;margin-bottom:12px;color:#0d6efd;display:flex;align-items:center;gap:8px}"
".tabs{display:flex;gap:4px;border-bottom:2px solid #dee2e6;margin-bottom:16px}"
".tab{padding:8px 16px;border:none;background:none;font-weight:600;cursor:pointer;color:#6c757d;border-radius:4px 4px 0 0}"
".tab.active{color:#0d6efd;border-bottom:3px solid #0d6efd;background:#fff}"
".pane{display:none;background:#fff;padding:16px;border-radius:6px;border:1px solid #dee2e6}"
".pane.active{display:block}"
"h2{font-size:1.05em;margin:16px 0 8px;color:#495057;border-bottom:1px solid #eee;padding-bottom:4px}"
"label{display:block;margin:6px 0 2px;font-size:.85em;font-weight:600}"
"input[type=text],input[type=number],input[type=password],select{width:100%;padding:6px;border:1px solid #ced4da;border-radius:4px;box-sizing:border-box}"
".row{display:flex;gap:8px}.row>div{flex:1}"
"button{padding:8px 16px;border:none;border-radius:4px;cursor:pointer;font-weight:600;font-size:.9em}"
".btn-pri{background:#0d6efd;color:#fff}.btn-pri:hover{background:#0b5ed7}"
".btn-dan{background:#dc3545;color:#fff}.btn-dan:hover{background:#bb2d3b}"
".alert{padding:10px;border-radius:4px;margin-bottom:12px;font-size:.85em}"
".alert-warn{background:#fff3cd;color:#664d03;border:1px solid #ffecb5}"
".status-box{background:#f8f9fa;border:1px solid #dee2e6;border-radius:4px;padding:12px;font-family:monospace;font-size:.88em;line-height:1.8}"
".ok{color:#198754;font-weight:bold}.err{color:#dc3545;font-weight:bold}"
"#prg{display:none;width:100%;height:12px;background:#e9ecef;border-radius:6px;overflow:hidden;margin-top:8px}"
"#prg-bar{width:0%;height:100%;background:#0d6efd;transition:width .2s}"
"</style></head><body>"
"<h1>&#9889; ESP32 Energy Gateway</h1>";

static const char HTML_FORM_TMPL[] =
"<div class=\"pane %s\" id=\"p1\">"
"<form id=\"cf\" onsubmit=\"saveCfg(event)\">"
"<h2>&#128268; Huawei SUN2000 SDongle</h2>"
"<label>IP-Adresse</label><input type=\"text\" name=\"h_ip\" value=\"%s\" required>"
"<div class=\"row\">"
"<div><label>Port</label><input type=\"number\" name=\"h_port\" value=\"%d\" min=\"1\" max=\"65535\"></div>"
"<div><label>Slave-ID WR 1</label><input type=\"number\" name=\"h_sid\" value=\"%d\" min=\"1\" max=\"247\"></div>"
"<div><label>Slave-ID WR 2 (0=aus)</label><input type=\"number\" name=\"h_sid2\" value=\"%d\" min=\"0\" max=\"247\"></div>"
"</div><div class=\"row\">"
"<div><label>Cache TTL (ms)</label><input type=\"number\" name=\"h_cache\" value=\"%d\" min=\"1000\" max=\"60000\" step=\"500\"></div>"
"<div><label>Max-Age (ms)</label><input type=\"number\" name=\"h_maxage\" value=\"%d\" min=\"3000\" max=\"60000\" step=\"500\"></div>"
"</div>"
"<label style=\"margin-top:8px\">Modbus Schreibzugriffe</label>"
"<select name=\"h_writes\">"
"<option value=\"0\" %s>0: Deaktiviert (Schreibbefehle sperren)</option>"
"<option value=\"1\" %s>1: Beobachtungsmodus (Schreibversuche nur loggen, nicht senden)</option>"
"<option value=\"2\" %s>2: Aktiviert (Huawei Speicher-Allowlist)</option>"
"</select>"

"<h2>&#9889; Shelly 3 EM (Gen1)</h2>"
"<label>IP-Adresse</label><input type=\"text\" name=\"s_ip\" value=\"%s\" required>"
"<div class=\"row\">"
"<div><label>Shelly HTTP Benutzer (optional)</label><input type=\"text\" name=\"s_usr\" value=\"%s\" placeholder=\"admin\"></div>"
"<div><label>Shelly HTTP Passwort (optional)</label><input type=\"password\" name=\"s_pwd\" value=\"%s\" placeholder=\"Passwort\"></div>"
"</div>"
"<label>Poll-Intervall (ms)</label><input type=\"number\" name=\"s_poll\" value=\"%d\" min=\"500\" max=\"10000\" step=\"100\">"
"<h2>Phasenzuordnung</h2><div class=\"row\">"
"<div><label>Phase A &#8592;</label><select name=\"pa\"><option %s>0</option><option %s>1</option><option %s>2</option></select></div>"
"<div><label>Phase B &#8592;</label><select name=\"pb\"><option %s>0</option><option %s>1</option><option %s>2</option></select></div>"
"<div><label>Phase C &#8592;</label><select name=\"pc\"><option %s>0</option><option %s>1</option><option %s>2</option></select></div>"
"</div>"

"<h2>&#128260; Zähler-Fallback (Huawei DTSU666-H)</h2>"
"<label>Automatischer Fallback bei Shelly-Ausfall</label>"
"<select name=\"m_fb\">"
"<option value=\"1\" %s>1: Aktiviert (Automatischer Fallback auf Huawei DTSU666-H)</option>"
"<option value=\"0\" %s>0: Deaktiviert</option>"
"</select>"

"<h2>&#128225; Integrierter MQTT-Broker (Port 1883)</h2>"
"<div class=\"row\">"
"<div><label>MQTT-Broker Status</label><select name=\"mq_en\"><option value=\"1\" %s>1: Aktiviert (Port 1883)</option><option value=\"0\" %s>0: Deaktiviert</option></select></div>"
"<div><label>Zähler-Betriebsmodus</label><select name=\"sh_mode\"><option value=\"1\" %s>1: Hybrid (MQTT Push primär, HTTP-Fallback)</option><option value=\"0\" %s>0: Nur HTTP-Polling</option></select></div>"
"</div>"
"<div class=\"row\">"
"<div><label>MQTT Benutzername (optional)</label><input type=\"text\" name=\"mq_usr\" value=\"%s\" placeholder=\"leer = anonym erlaubt\"></div>"
"<div><label>MQTT Passwort (optional)</label><input type=\"password\" name=\"mq_pwd\" value=\"%s\" placeholder=\"Passwort\"></div>"
"</div>"

"<h2>&#128272; Administrator-Passwort</h2>"
"<label>Neues Passwort (leer lassen für keine Änderung)</label>"
"<input type=\"password\" name=\"adm_pw\" placeholder=\"Neues Passwort eingeben\">"

"<h2>&#127760; Netzwerk</h2>"
"<label><input type=\"radio\" name=\"dhcp\" value=\"1\" %s onchange=\"document.getElementById('sf').style.display='none'\"> DHCP (empfohlen)</label>"
"<label><input type=\"radio\" name=\"dhcp\" value=\"0\" %s onchange=\"document.getElementById('sf').style.display='block'\"> Statische IP</label>"
"<div id=\"sf\" style=\"display:%s;margin-top:6px\"><div class=\"row\">"
"<div><label>IP</label><input type=\"text\" name=\"sip\" value=\"%s\"></div>"
"<div><label>Gateway</label><input type=\"text\" name=\"sgw\" value=\"%s\"></div>"
"<div><label>Subnetz</label><input type=\"text\" name=\"snm\" value=\"%s\"></div>"
"</div></div>"
"<br><button type=\"submit\" class=\"btn-pri\">&#128190; Speichern &amp; Neustart</button>"
"</form></div>";

static const char HTML_STATIC_FOOT[] =
"<div class=\"pane\" id=\"p2\">"
"<h2>&#128260; Web OTA Firmware-Update</h2>"
"<p style=\"font-size:.88em;color:#6c757d\">Wähle eine kompilierte <code>firmware.bin</code> zum Hochladen aus. Der ESP32 prüft das Image und bootet automatisch neu.</p>"
"<input type=\"file\" id=\"uf\" accept=\".bin\"><br><br>"
"<button class=\"btn-pri\" onclick=\"uploadOTA()\">&#11014; Firmware jetzt flashen</button>"
"<div id=\"prg\"><div id=\"prg-bar\"></div></div>"
"<div id=\"ota-msg\" style=\"margin-top:8px;font-size:.88em\"></div>"
"</div>"

"<script>"
"function sw(i){"
"document.querySelectorAll('.tab').forEach((t,j)=>t.classList.toggle('active',i===j));"
"document.querySelectorAll('.pane').forEach((p,j)=>p.classList.toggle('active',i===j));"
"}"
"function upd(){"
"fetch('/api/status').then(r=>r.json()).then(d=>{"
"let srcTag='<span class=err>Kein Zähler</span>';"
"if(d.src==='mqtt')srcTag='<span class=ok style=\"color:#0dcaf0\">&#9889; Shelly 3 EM (MQTT Push, &lt; 10ms)</span>';"
"else if(d.src==='shelly')srcTag='<span class=ok>&#10003; Shelly 3 EM (HTTP Poll)</span>';"
"else if(d.src==='huawei')srcTag='<span class=ok style=\"color:#e0a800\">&#9888; Huawei DTSU666-H (Fallback aktiv)</span>';"
"document.getElementById('st').innerHTML="
"'<b>Ethernet IP:</b> '+(d.eth?'<span class=ok>'+d.ip+'</span>':'<span class=err>Getrennt</span>')+'<br>'"
"+'<b>Hostname:</b> esp32-energy-gateway (DHCP)<br>'"
"+'<b>Zähler-Quelle:</b> '+srcTag+'<br>'"
"+'<b>MQTT Broker (:1883):</b> '+(d.mq_clients>0?'<span class=ok>'+d.mq_clients+' Client(s) verbunden</span>':'<span style=\"color:#6c757d\">Warte auf Verbindung (0 Clients)</span>')+(d.mq_cli?' | Letzter: '+d.mq_cli+' ('+Math.round(d.mq_age/1000)+'s, '+d.mq_msgs+' msgs)': '')+'<br>'"
"+'<b>Shelly 3 EM:</b> '+(d.sh_ok?'<span class=ok>&#10003; Erreichbar ('+d.sh_age+' ms)</span>':'<span class=err>&#10007; Nicht erreichbar ('+(d.sh_err||'Fehler')+')</span>')+'<br>'"
"+'<b>SDongle Upstream:</b> '+(d.mb_up?'<span class=ok>&#10003; Verbunden</span>':'<span class=err>&#10007; Getrennt '+(d.mb_err?'('+d.mb_err+')':'')+'</span>')+'<br>'"
"+'<b>Modbus Clients:</b> '+d.mb_clients+' | <b>Cache Hits:</b> '+d.mb_hits+' | <b>Misses:</b> '+d.mb_misses+'<br>'"
"+'<b>Marstek / Shelly UDP:</b> '+d.udp_rx+' empf / '+d.udp_tx+' ges (CT: '+d.udp_ct+', RPC: '+d.udp_rpc+')'+(d.udp_cli?' | Letzter: '+d.udp_cli+' ('+d.udp_proto+', '+Math.round(d.udp_age/1000)+'s)': '')+'<br>'"
"+'<b>Freier Heap:</b> '+Math.round(d.heap/1024)+' KB | <b>Uptime:</b> '+d.uptime+' s';"
"}).catch(e=>{document.getElementById('st').innerHTML='Statusfehler: '+e;});"
"fetch('/api/writes').then(r=>r.json()).then(w=>{"
"if(!w||w.length===0){document.getElementById('wl').innerHTML='<i>Keine Schreibversuche aufgezeichnet</i>';return;}"
"let h='<table style=\"width:100%;border-collapse:collapse;font-size:0.85em\">"
"<tr style=\"border-bottom:1px solid #ccc;text-align:left\"><th>Zeit</th><th>UID</th><th>FC</th><th>Reg</th><th>Cnt</th><th>Wert</th><th>Status</th></tr>';"
"w.forEach(e=>{"
"h+='<tr style=\"border-bottom:1px solid #eee\"><td>'+e.t+'s</td><td>'+e.uid+'</td><td>FC'+e.fc+'</td><td>'+e.addr+'</td><td>'+e.cnt+'</td><td>'+e.val+'</td><td>'+(e.ok?'<span class=ok>Erlaubt</span>':'<span class=err>Blockiert (0x0'+e.exc.toString(16)+')</span>')+'</td></tr>';"
"});"
"h+='</table>';"
"document.getElementById('wl').innerHTML=h;"
"}).catch(()=>{});"
"}"
"upd();"
"setInterval(upd,3000);"
"function saveCfg(e){"
"e.preventDefault();"
"const f=new FormData(e.target);"
"const o={};"
"f.forEach((v,k)=>o[k]=v);"
"o.h_writes=parseInt(f.get('h_writes'),10)||0;"
"fetch('/config',{"
"method:'POST',"
"headers:{'Content-Type':'application/json','X-Requested-With':'XMLHttpRequest'},"
"body:JSON.stringify(o)"
"}).then(r=>{"
"if(r.ok){"
"alert('Gespeichert. Neustart...');"
"setTimeout(()=>location.reload(),4000);"
"}else{"
"r.json().then(j=>alert('Fehler: '+(j.reason||j.error)));"
"}"
"}).catch(err=>alert('Netzwerkfehler: '+err));"
"}"
"function resetNVS(){"
"if(confirm('Wirklich Werkseinstellungen laden?')){"
"fetch('/api/reset',{method:'POST',headers:{'X-Requested-With':'XMLHttpRequest'}})"
".then(()=>alert('Gerät wird zurückgesetzt und startet neu...'))"
".catch(err=>alert('Fehler: '+err));"
"}"
"}"
"function uploadOTA(){"
"const f=document.getElementById('uf').files[0];"
"if(!f){alert('Bitte Datei wählen');return;}"
"const p=document.getElementById('prg');"
"const pb=document.getElementById('prg-bar');"
"const m=document.getElementById('ota-msg');"
"p.style.display='block';"
"pb.style.width='0%';"
"m.innerHTML='Lade hoch...';"
"const x=new XMLHttpRequest();"
"x.open('POST','/update',true);"
"x.setRequestHeader('X-Requested-With','XMLHttpRequest');"
"x.upload.onprogress=e=>{"
"if(e.lengthComputable){pb.style.width=Math.round((e.loaded/e.total)*100)+'%';}"
"};"
"x.onload=()=>{"
"if(x.status===200){"
"m.innerHTML='<span class=ok>Update erfolgreich! Neustart...</span>';"
"setTimeout(()=>location.reload(),6000);"
"}else{"
"m.innerHTML='<span class=err>Fehler: '+x.responseText+'</span>';"
"}"
"};"
"x.onerror=()=>m.innerHTML='<span class=err>Netzwerkfehler beim Upload</span>';"
"x.send(f);"
"}"
"</script></body></html>";

/* ------------------------------------------------------------------ */
/*  Handlers                                                            */
/* ------------------------------------------------------------------ */

static esp_err_t handler_root_get(httpd_req_t *req)
{
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "/config");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

static esp_err_t handler_config_get(httpd_req_t *req)
{
    if (!check_auth(req)) return send_unauthorized(req);

    httpd_resp_set_type(req, "text/html; charset=utf-8");

    /* 1. Header and styles */
    httpd_resp_sendstr_chunk(req, HTML_STATIC_HEAD);

    /* 2. Alert if first time */
    bool is_first_setup = (g_cfg.admin_pw_hash[0] == '\0' && g_cfg.admin_password[0] == '\0');
    if (is_first_setup) {
        httpd_resp_sendstr_chunk(req,
            "<div class=\"alert alert-warn\">&#9888; <b>Ersteinrichtung:</b> "
            "Bitte vergebe im Reiter &laquo;Einstellungen&raquo; ein Administrator-Passwort!</div>");
    }

    /* 3. Tabs navigation: default to Tab 1 if first-time setup, otherwise Tab 0 */
    char tab_nav[1024];
    int nav_len = snprintf(tab_nav, sizeof(tab_nav),
        "<div class=\"tabs\">"
        "<button class=\"tab %s\" onclick=\"sw(0)\">&#128202; Status</button>"
        "<button class=\"tab %s\" onclick=\"sw(1)\">&#9881; Einstellungen</button>"
        "<button class=\"tab\" onclick=\"sw(2)\">&#128260; Firmware-Update</button>"
        "</div>"
        "<div class=\"pane %s\" id=\"p0\">"
        "<div class=\"status-box\" id=\"st\">Lade Status&#8230;</div>"
        "<h2 style=\"margin-top:16px\">&#128221; Letzte Modbus-Schreibversuche</h2>"
        "<div id=\"wl\" class=\"status-box\" style=\"font-size:.8em;overflow-x:auto\">Keine Schreibversuche aufgezeichnet</div>"
        "<div style=\"margin-top:12px\"><button class=\"btn-dan\" onclick=\"resetNVS()\">&#8635; Werkseinstellungen</button></div>"
        "</div>",
        is_first_setup ? "" : "active",
        is_first_setup ? "active" : "",
        is_first_setup ? "" : "active"
    );
    if (nav_len < 0 || (size_t)nav_len >= sizeof(tab_nav)) {
        ESP_LOGE(TAG, "tab_nav buffer overflow");
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    httpd_resp_sendstr_chunk(req, tab_nav);

    /* 4. Tab 1: Config Form */
    char *form_buf = malloc(5120);
    if (!form_buf) {
        httpd_resp_sendstr_chunk(req, NULL);
        return ESP_FAIL;
    }

    /* Escape all string variables to prevent HTML/attribute injection */
    char esc_h_ip[64], esc_s_ip[64], esc_s_usr[64], esc_s_pwd[64], esc_sip[64], esc_sgw[64], esc_snm[64];
    char esc_mq_usr[64], esc_mq_pwd[64];
    html_escape(g_cfg.huawei_ip, esc_h_ip, sizeof(esc_h_ip));
    html_escape(g_cfg.shelly_ip, esc_s_ip, sizeof(esc_s_ip));
    html_escape(g_cfg.shelly_user, esc_s_usr, sizeof(esc_s_usr));
    html_escape(g_cfg.shelly_pass, esc_s_pwd, sizeof(esc_s_pwd));
    html_escape(g_cfg.mqtt_user, esc_mq_usr, sizeof(esc_mq_usr));
    html_escape(g_cfg.mqtt_pass, esc_mq_pwd, sizeof(esc_mq_pwd));
    html_escape(g_cfg.static_ip, esc_sip, sizeof(esc_sip));
    html_escape(g_cfg.static_gw, esc_sgw, sizeof(esc_sgw));
    html_escape(g_cfg.static_nm, esc_snm, sizeof(esc_snm));

#define S(val, idx) ((val) == (idx) ? "selected" : "")
    int form_len = snprintf(form_buf, 5120, HTML_FORM_TMPL,
        is_first_setup ? "active" : "",
        esc_h_ip,
        g_cfg.huawei_port,
        g_cfg.huawei_slave_id,
        g_cfg.huawei_slave_id_2,
        g_cfg.modbus_cache_ms,
        g_cfg.modbus_max_age_ms,
        S(g_cfg.modbus_allow_writes, 0),
        S(g_cfg.modbus_allow_writes, 1),
        S(g_cfg.modbus_allow_writes, 2),
        esc_s_ip,
        esc_s_usr,
        esc_s_pwd,
        g_cfg.shelly_poll_ms,
        S(g_cfg.phase_map[0], 0), S(g_cfg.phase_map[0], 1), S(g_cfg.phase_map[0], 2),
        S(g_cfg.phase_map[1], 0), S(g_cfg.phase_map[1], 1), S(g_cfg.phase_map[1], 2),
        S(g_cfg.phase_map[2], 0), S(g_cfg.phase_map[2], 1), S(g_cfg.phase_map[2], 2),
        S(g_cfg.meter_fallback_enabled, 1), S(g_cfg.meter_fallback_enabled, 0),
        S(g_cfg.mqtt_broker_enabled, 1), S(g_cfg.mqtt_broker_enabled, 0),
        S(g_cfg.shelly_source_mode, 1), S(g_cfg.shelly_source_mode, 0),
        esc_mq_usr,
        esc_mq_pwd,
        g_cfg.use_static_ip == 0 ? "checked" : "",
        g_cfg.use_static_ip == 1 ? "checked" : "",
        g_cfg.use_static_ip == 1 ? "block" : "none",
        esc_sip,
        esc_sgw,
        esc_snm
    );
#undef S

    if (form_len < 0 || (size_t)form_len >= 5120) {
        ESP_LOGE(TAG, "form_buf buffer overflow or error: %d", form_len);
        free(form_buf);
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    httpd_resp_sendstr_chunk(req, form_buf);
    free(form_buf);

    /* 5. Tab 2: OTA & JavaScript Footer */
    httpd_resp_sendstr_chunk(req, HTML_STATIC_FOOT);

    /* Terminate chunked response */
    httpd_resp_sendstr_chunk(req, NULL);
    return ESP_OK;
}

static esp_err_t handler_config_post(httpd_req_t *req)
{
    if (!check_auth(req)) return send_unauthorized(req);
    if (!check_csrf(req)) return send_forbidden(req, "CSRF validation failed");

    int total_len = req->content_len;
    if (total_len <= 0 || total_len > 2048) {
        return send_forbidden(req, "Invalid payload length");
    }

    char *body = malloc(total_len + 1);
    if (!body) { httpd_resp_send_500(req); return ESP_FAIL; }

    int cur = 0;
    while (cur < total_len) {
        int r = httpd_req_recv(req, body + cur, total_len - cur);
        if (r <= 0) { free(body); httpd_resp_send_500(req); return ESP_FAIL; }
        cur += r;
    }
    body[total_len] = '\0';

    cJSON *json = cJSON_Parse(body);
    free(body);
    if (!json) return send_forbidden(req, "JSON parse error");

    gateway_config_t new_cfg;
    memcpy(&new_cfg, &g_cfg, sizeof(new_cfg));

#define GET_STR(j, key, dst) do { \
    cJSON *_x = cJSON_GetObjectItemCaseSensitive(j, key); \
    if (cJSON_IsString(_x) && _x->valuestring[0]) strncpy(dst, _x->valuestring, sizeof(dst)-1); \
} while(0)

#define GET_INT(j, key, dst, min_v, max_v) do { \
    cJSON *_x = cJSON_GetObjectItemCaseSensitive(j, key); \
    int _v = 0; \
    if (cJSON_IsNumber(_x)) _v = (int)_x->valuedouble; \
    else if (cJSON_IsString(_x)) _v = atoi(_x->valuestring); \
    if (_v >= (min_v) && _v <= (max_v)) dst = _v; \
} while(0)

    GET_STR(json, "h_ip", new_cfg.huawei_ip);
    GET_INT(json, "h_port", new_cfg.huawei_port, 1, 65535);
    GET_INT(json, "h_sid", new_cfg.huawei_slave_id, 1, 247);
    GET_INT(json, "h_sid2", new_cfg.huawei_slave_id_2, 0, 247);
    GET_INT(json, "h_cache", new_cfg.modbus_cache_ms, 1000, 60000);
    GET_INT(json, "h_maxage", new_cfg.modbus_max_age_ms, 3000, 60000);
    GET_INT(json, "h_writes", new_cfg.modbus_allow_writes, 0, 2);

    GET_STR(json, "s_ip", new_cfg.shelly_ip);
    GET_STR(json, "s_usr", new_cfg.shelly_user);
    GET_STR(json, "s_pwd", new_cfg.shelly_pass);
    GET_INT(json, "s_poll", new_cfg.shelly_poll_ms, 500, 10000);
    GET_INT(json, "pa", new_cfg.phase_map[0], 0, 2);
    GET_INT(json, "pb", new_cfg.phase_map[1], 0, 2);
    GET_INT(json, "pc", new_cfg.phase_map[2], 0, 2);
    GET_INT(json, "m_fb", new_cfg.meter_fallback_enabled, 0, 1);

    GET_INT(json, "mq_en", new_cfg.mqtt_broker_enabled, 0, 1);
    GET_INT(json, "sh_mode", new_cfg.shelly_source_mode, 0, 1);
    GET_STR(json, "mq_usr", new_cfg.mqtt_user);
    GET_STR(json, "mq_pwd", new_cfg.mqtt_pass);

    /* Password update: compute salted SHA-256 hash */
    cJSON *pw_item = cJSON_GetObjectItemCaseSensitive(json, "adm_pw");
    if (cJSON_IsString(pw_item) && strlen(pw_item->valuestring) >= 4) {
        uint8_t rnd[8];
        esp_fill_random(rnd, sizeof(rnd));
        for (int i = 0; i < 8; i++) snprintf(&new_cfg.admin_pw_salt[i * 2], 3, "%02x", rnd[i]);
        new_cfg.admin_pw_salt[16] = '\0';

        char to_hash[128];
        snprintf(to_hash, sizeof(to_hash), "%s%s", new_cfg.admin_pw_salt, pw_item->valuestring);
        uint8_t hash_out[32];
        mbedtls_sha256((const unsigned char *)to_hash, strlen(to_hash), hash_out, 0);
        for (int i = 0; i < 32; i++) snprintf(&new_cfg.admin_pw_hash[i * 2], 3, "%02x", hash_out[i]);
        new_cfg.admin_pw_hash[64] = '\0';
        new_cfg.admin_password[0] = '\0';
    }

    /* Network validation */
    cJSON *dhcp_item = cJSON_GetObjectItemCaseSensitive(json, "dhcp");
    int dhcp_val = 1;
    if (cJSON_IsNumber(dhcp_item)) dhcp_val = (int)dhcp_item->valuedouble;
    else if (cJSON_IsString(dhcp_item)) dhcp_val = atoi(dhcp_item->valuestring);
    new_cfg.use_static_ip = (dhcp_val == 0) ? 1 : 0;

    if (new_cfg.use_static_ip) {
        esp_netif_ip_info_t chk;
        GET_STR(json, "sip", new_cfg.static_ip);
        GET_STR(json, "sgw", new_cfg.static_gw);
        GET_STR(json, "snm", new_cfg.static_nm);
        if (esp_netif_str_to_ip4(new_cfg.static_ip, &chk.ip) != ESP_OK ||
            esp_netif_str_to_ip4(new_cfg.static_gw, &chk.gw) != ESP_OK ||
            esp_netif_str_to_ip4(new_cfg.static_nm, &chk.netmask) != ESP_OK) {
            cJSON_Delete(json);
            return send_forbidden(req, "Ungültige statische IP-Adresse!");
        }
    }

#undef GET_STR
#undef GET_INT

    cJSON_Delete(json);

    memcpy(&g_cfg, &new_cfg, sizeof(g_cfg));
    config_save(&new_cfg);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, "{\"status\":\"ok\"}", HTTPD_RESP_USE_STRLEN);
    schedule_reboot(1000);
    return ESP_OK;
}

static esp_err_t handler_update_post(httpd_req_t *req)
{
    if (!check_auth(req)) return send_unauthorized(req);
    if (!check_csrf(req)) return send_forbidden(req, "CSRF check failed");

    const esp_partition_t *update_partition = esp_ota_get_next_update_partition(NULL);
    if (!update_partition) {
        ESP_LOGE(TAG, "No OTA partition found");
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Writing OTA to partition %s (offset 0x%lx, size %lu)",
             update_partition->label, update_partition->address, update_partition->size);

    esp_ota_handle_t ota_handle = 0;
    esp_err_t err = esp_ota_begin(update_partition, OTA_WITH_SEQUENTIAL_WRITES, &ota_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_begin failed: %s", esp_err_to_name(err));
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    char *buf = malloc(1024);
    if (!buf) {
        esp_ota_abort(ota_handle);
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    int remaining = req->content_len;
    bool first_chunk = true;

    while (remaining > 0) {
        int to_read = remaining > 1024 ? 1024 : remaining;
        int ret = httpd_req_recv(req, buf, to_read);
        if (ret <= 0) {
            ESP_LOGE(TAG, "OTA receive error");
            esp_ota_abort(ota_handle);
            free(buf);
            httpd_resp_send_500(req);
            return ESP_FAIL;
        }

        if (first_chunk) {
            if ((uint8_t)buf[0] != 0xE9) {
                ESP_LOGE(TAG, "Invalid firmware magic byte (0x%02X != 0xE9)", (uint8_t)buf[0]);
                esp_ota_abort(ota_handle);
                free(buf);
                httpd_resp_set_status(req, "400 Bad Request");
                httpd_resp_send(req, "Ungültiges Firmware-Image (Magic Byte)", HTTPD_RESP_USE_STRLEN);
                return ESP_OK;
            }
            first_chunk = false;
        }

        err = esp_ota_write(ota_handle, buf, ret);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "esp_ota_write failed: %s", esp_err_to_name(err));
            esp_ota_abort(ota_handle);
            free(buf);
            httpd_resp_send_500(req);
            return ESP_FAIL;
        }
        remaining -= ret;
    }
    free(buf);

    err = esp_ota_end(ota_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_end failed: %s", esp_err_to_name(err));
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    err = esp_ota_set_boot_partition(update_partition);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_set_boot_partition failed: %s", esp_err_to_name(err));
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "OTA flash complete. Scheduling reboot in 1s");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, "{\"status\":\"ok\"}", HTTPD_RESP_USE_STRLEN);
    schedule_reboot(1000);
    return ESP_OK;
}

static esp_err_t handler_api_status_get(httpd_req_t *req)
{
    int64_t now_ms = esp_timer_get_time() / 1000LL;

    shelly_data_snapshot_t snap;
    bool sh_ok = data_store_get_shelly_snapshot(&snap) && snap.shelly_valid;
    int64_t sh_age = sh_ok && (now_ms >= snap.shelly_last_update_ms) ? (now_ms - snap.shelly_last_update_ms) : 0;

    DATA_LOCK();
    bool eth_connected = g_data.eth_connected;
    char eth_ip[20];
    memcpy(eth_ip, g_data.eth_ip, sizeof(eth_ip));
    bool mb_up = g_data.mb_upstream_connected;
    char mb_err[64];
    strncpy(mb_err, g_data.mb_upstream_err, sizeof(mb_err) - 1);
    mb_err[sizeof(mb_err) - 1] = '\0';
    uint8_t mb_clients = g_data.mb_client_count;
    uint32_t mb_hits = g_data.mb_cache_hits;
    uint32_t mb_misses = g_data.mb_cache_misses;

    uint32_t udp_rx  = g_data.udp_rx_count;
    uint32_t udp_tx  = g_data.udp_tx_count;
    uint32_t udp_ct  = g_data.udp_ct002_count;
    uint32_t udp_rpc = g_data.udp_rpc_count;
    char udp_cli[32];
    strncpy(udp_cli, g_data.udp_last_client, sizeof(udp_cli) - 1);
    udp_cli[sizeof(udp_cli) - 1] = '\0';
    char udp_proto[16];
    strncpy(udp_proto, g_data.udp_last_proto, sizeof(udp_proto) - 1);
    udp_proto[sizeof(udp_proto) - 1] = '\0';
    int64_t udp_age = (g_data.udp_last_rx_ms > 0 && now_ms >= g_data.udp_last_rx_ms) ? (now_ms - g_data.udp_last_rx_ms) : -1;
    char sh_err[64];
    strncpy(sh_err, g_data.sh_err, sizeof(sh_err) - 1);
    sh_err[sizeof(sh_err) - 1] = '\0';

    uint8_t mq_clients = g_data.mqtt_clients_count;
    uint32_t mq_msgs = g_data.mqtt_rx_msgs;
    char mq_cli[32];
    strncpy(mq_cli, g_data.mqtt_last_client, sizeof(mq_cli) - 1);
    mq_cli[sizeof(mq_cli) - 1] = '\0';
    int64_t mq_age = (g_data.mqtt_last_rx_ms > 0 && now_ms >= g_data.mqtt_last_rx_ms) ? (now_ms - g_data.mqtt_last_rx_ms) : -1;
    DATA_UNLOCK();

    const char *src_str = "none";
    if (sh_ok) {
        if (snap.active_meter_source == METER_SRC_MQTT) src_str = "mqtt";
        else if (snap.active_meter_source == METER_SRC_HUAWEI) src_str = "huawei";
        else src_str = "shelly";
    }

    char buf[1280];
    int len = snprintf(buf, sizeof(buf),
        "{\"eth\":%s,\"ip\":\"%s\","
        "\"src\":\"%s\",\"sh_ok\":%s,\"sh_err\":\"%s\",\"sh_age\":%lld,"
        "\"mb_up\":%s,\"mb_err\":\"%s\",\"mb_clients\":%u,\"mb_hits\":%lu,\"mb_misses\":%lu,"
        "\"udp_rx\":%lu,\"udp_tx\":%lu,\"udp_ct\":%lu,\"udp_rpc\":%lu,"
        "\"udp_cli\":\"%s\",\"udp_proto\":\"%s\",\"udp_age\":%lld,"
        "\"mq_clients\":%u,\"mq_msgs\":%lu,\"mq_cli\":\"%s\",\"mq_age\":%lld,"
        "\"heap\":%lu,\"uptime\":%lu}",
        eth_connected ? "true" : "false", eth_ip,
        src_str,
        sh_ok ? "true" : "false", sh_err, (long long)sh_age,
        mb_up ? "true" : "false", mb_err, mb_clients,
        (unsigned long)mb_hits, (unsigned long)mb_misses,
        (unsigned long)udp_rx, (unsigned long)udp_tx, (unsigned long)udp_ct, (unsigned long)udp_rpc,
        udp_cli, udp_proto, (long long)udp_age,
        mq_clients, (unsigned long)mq_msgs, mq_cli, (long long)mq_age,
        (unsigned long)esp_get_free_heap_size(),
        (unsigned long)(now_ms / 1000LL)
    );
    if (len >= (int)sizeof(buf)) len = sizeof(buf) - 1;

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, buf, len);
    return ESP_OK;
}

static esp_err_t handler_api_writes_get(httpd_req_t *req)
{
    char *buf = malloc(2048);
    if (!buf) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    int len = modbus_proxy_get_write_log_json(buf, 2048);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, buf, len);
    free(buf);
    return ESP_OK;
}

static esp_err_t handler_api_reset_post(httpd_req_t *req)
{
    if (!check_auth(req)) return send_unauthorized(req);
    if (!check_csrf(req)) return send_forbidden(req, "CSRF check failed");

    nvs_flash_erase();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, "{\"status\":\"resetting\"}", HTTPD_RESP_USE_STRLEN);
    schedule_reboot(1000);
    return ESP_OK;
}

/* ------------------------------------------------------------------ */
/*  Shelly Gen2 Endpoints (EM, EMData, Shelly.GetStatus)               */
/* ------------------------------------------------------------------ */

static esp_err_t handler_shelly_device_info_get(httpd_req_t *req)
{
    char mac[13], dev_id[32];
    get_device_identity(mac, sizeof(mac), dev_id, sizeof(dev_id));

    char buf[256];
    int len = snprintf(buf, sizeof(buf),
        "{\"id\":\"%s\",\"mac\":\"%s\","
        "\"model\":\"SPEM-003CEBEU\",\"gen\":2,"
        "\"fw_id\":\"20240101-120000/v1.4.0-esp32gw\","
        "\"ver\":\"1.4.0\",\"app\":\"Pro3EM\",\"profile\":\"em\"}",
        dev_id, mac);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, buf, len);
    return ESP_OK;
}

static esp_err_t handler_em_get_config_get(httpd_req_t *req)
{
    static const char resp[] =
        "{\"id\":0,\"name\":null,\"blink_mode_selector\":\"all\","
        "\"phase_selector\":\"all\",\"monitor_phase_sequence\":true,"
        "\"ct_type\":\"120A\",\"reverse\":{}}";

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

static esp_err_t handler_em_get_ct_types_get(httpd_req_t *req)
{
    static const char resp[] = "[\"120A\",\"400A\",\"50A\"]";
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

static esp_err_t handler_shelly_get_config_get(httpd_req_t *req)
{
    static const char resp[] =
        "{\"em:0\":{\"id\":0,\"name\":null,\"blink_mode_selector\":\"all\","
        "\"phase_selector\":\"all\",\"monitor_phase_sequence\":true,"
        "\"ct_type\":\"120A\"},"
        "\"em\":{\"id\":0,\"phase_selector\":\"all\",\"ct_type\":\"120A\","
        "\"ct_types\":[\"120A\",\"120A\",\"120A\"]}}";

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, resp, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

static esp_err_t handler_em_get_status_get(httpd_req_t *req)
{
    shelly_data_snapshot_t snap;
    if (!data_store_get_shelly_snapshot(&snap) || !snap.shelly_valid) {
        httpd_resp_set_status(req, "503 Service Unavailable");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, "{\"error\":{\"code\":-32000,\"message\":\"Sensor data unavailable\"}}", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }

    int64_t age = (esp_timer_get_time() / 1000LL) - snap.shelly_last_update_ms;
    if (age > STALE_THRESHOLD_MS) {
        httpd_resp_set_status(req, "503 Service Unavailable");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, "{\"error\":{\"code\":-32000,\"message\":\"Sensor data stale\"}}", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }

    char *buf = malloc(1024);
    if (!buf) { httpd_resp_send_500(req); return ESP_FAIL; }

    int len = snprintf(buf, 1024,
        "{"
        "\"id\":0,"
        "\"ct_state\":1,"
        "\"a_current\":%.4f,\"a_voltage\":%.4f,"
        "\"a_act_power\":%.4f,\"a_aprt_power\":%.4f,"
        "\"a_pf\":%.4f,\"a_freq\":%.4f,"
        "\"b_current\":%.4f,\"b_voltage\":%.4f,"
        "\"b_act_power\":%.4f,\"b_aprt_power\":%.4f,"
        "\"b_pf\":%.4f,\"b_freq\":%.4f,"
        "\"c_current\":%.4f,\"c_voltage\":%.4f,"
        "\"c_act_power\":%.4f,\"c_aprt_power\":%.4f,"
        "\"c_pf\":%.4f,\"c_freq\":%.4f,"
        "\"n_current\":null,"
        "\"total_current\":%.4f,"
        "\"total_act_power\":%.4f,"
        "\"total_aprt_power\":%.4f,"
        "\"user_calibrated_phase\":[]"
        "}",
        snap.a_current, snap.a_voltage, snap.a_act_power, snap.a_aprt_power, snap.a_pf, snap.a_freq,
        snap.b_current, snap.b_voltage, snap.b_act_power, snap.b_aprt_power, snap.b_pf, snap.b_freq,
        snap.c_current, snap.c_voltage, snap.c_act_power, snap.c_aprt_power, snap.c_pf, snap.c_freq,
        snap.total_current, snap.total_act_power, snap.total_aprt_power
    );

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, buf, len);
    free(buf);
    return ESP_OK;
}

static esp_err_t handler_emdata_get_status_get(httpd_req_t *req)
{
    shelly_data_snapshot_t snap;
    if (!data_store_get_shelly_snapshot(&snap) || !snap.shelly_valid) {
        httpd_resp_set_status(req, "503 Service Unavailable");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, "{\"error\":{\"code\":-32000,\"message\":\"Sensor data unavailable\"}}", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }

    int64_t age = (esp_timer_get_time() / 1000LL) - snap.shelly_last_update_ms;
    if (age > STALE_THRESHOLD_MS) {
        httpd_resp_set_status(req, "503 Service Unavailable");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, "{\"error\":{\"code\":-32000,\"message\":\"Sensor data stale\"}}", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }

    char buf[384];
    int len = snprintf(buf, sizeof(buf),
        "{\"id\":0,"
        "\"a_total_act_energy\":%.2f,\"a_total_act_ret_energy\":%.2f,"
        "\"b_total_act_energy\":%.2f,\"b_total_act_ret_energy\":%.2f,"
        "\"c_total_act_energy\":%.2f,\"c_total_act_ret_energy\":%.2f,"
        "\"total_act\":%.2f,\"total_act_ret\":%.2f}",
        snap.a_total_wh, snap.a_total_ret_wh,
        snap.b_total_wh, snap.b_total_ret_wh,
        snap.c_total_wh, snap.c_total_ret_wh,
        snap.total_act_wh, snap.total_act_ret_wh
    );

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, buf, len);
    return ESP_OK;
}

static esp_err_t handler_shelly_get_status_get(httpd_req_t *req)
{
    shelly_data_snapshot_t snap;
    if (!data_store_get_shelly_snapshot(&snap) || !snap.shelly_valid) {
        httpd_resp_set_status(req, "503 Service Unavailable");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, "{\"error\":{\"code\":-32000,\"message\":\"Sensor data unavailable\"}}", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }

    int64_t age = (esp_timer_get_time() / 1000LL) - snap.shelly_last_update_ms;
    if (age > STALE_THRESHOLD_MS) {
        httpd_resp_set_status(req, "503 Service Unavailable");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, "{\"error\":{\"code\":-32000,\"message\":\"Sensor data stale\"}}", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }

    char eth_ip[20];
    DATA_LOCK();
    memcpy(eth_ip, g_data.eth_ip, sizeof(eth_ip));
    DATA_UNLOCK();

    char mac[13], dev_id[32];
    get_device_identity(mac, sizeof(mac), dev_id, sizeof(dev_id));
    uint32_t uptime_sec = (uint32_t)(esp_timer_get_time() / 1000000ULL);

    char *buf = malloc(1536);
    if (!buf) { httpd_resp_send_500(req); return ESP_FAIL; }

    int len = snprintf(buf, 1536,
        "{"
        "\"ble\":{},\"cloud\":{\"connected\":false},"
        "\"em:0\":{"
        "\"id\":0,"
        "\"ct_state\":1,"
        "\"a_current\":%.4f,\"a_voltage\":%.4f,\"a_act_power\":%.4f,\"a_aprt_power\":%.4f,\"a_pf\":%.4f,\"a_freq\":%.4f,"
        "\"b_current\":%.4f,\"b_voltage\":%.4f,\"b_act_power\":%.4f,\"b_aprt_power\":%.4f,\"b_pf\":%.4f,\"b_freq\":%.4f,"
        "\"c_current\":%.4f,\"c_voltage\":%.4f,\"c_act_power\":%.4f,\"c_aprt_power\":%.4f,\"c_pf\":%.4f,\"c_freq\":%.4f,"
        "\"n_current\":null,\"total_current\":%.4f,\"total_act_power\":%.4f,\"total_aprt_power\":%.4f,\"user_calibrated_phase\":[]"
        "},"
        "\"emdata:0\":{"
        "\"id\":0,"
        "\"a_total_act_energy\":%.2f,\"a_total_act_ret_energy\":%.2f,"
        "\"b_total_act_energy\":%.2f,\"b_total_act_ret_energy\":%.2f,"
        "\"c_total_act_energy\":%.2f,\"c_total_act_ret_energy\":%.2f,"
        "\"total_act\":%.2f,\"total_act_ret\":%.2f"
        "},"
        "\"eth\":{\"ip\":\"%s\"},"
        "\"sys\":{\"mac\":\"%s\",\"restart_required\":false,\"uptime\":%lu}"
        "}",
        snap.a_current, snap.a_voltage, snap.a_act_power, snap.a_aprt_power, snap.a_pf, snap.a_freq,
        snap.b_current, snap.b_voltage, snap.b_act_power, snap.b_aprt_power, snap.b_pf, snap.b_freq,
        snap.c_current, snap.c_voltage, snap.c_act_power, snap.c_aprt_power, snap.c_pf, snap.c_freq,
        snap.total_current, snap.total_act_power, snap.total_aprt_power,
        snap.a_total_wh, snap.a_total_ret_wh,
        snap.b_total_wh, snap.b_total_ret_wh,
        snap.c_total_wh, snap.c_total_ret_wh,
        snap.total_act_wh, snap.total_act_ret_wh,
        eth_ip, mac, (unsigned long)uptime_sec
    );

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, buf, len);
    free(buf);
    return ESP_OK;
}

static esp_err_t handler_gen1_status_get(httpd_req_t *req)
{
    shelly_data_snapshot_t snap;
    if (!data_store_get_shelly_snapshot(&snap) || !snap.shelly_valid) {
        httpd_resp_set_status(req, "503 Service Unavailable");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, "{\"error\":\"Sensor data unavailable\"}", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }

    char eth_ip[20];
    DATA_LOCK();
    memcpy(eth_ip, g_data.eth_ip, sizeof(eth_ip));
    DATA_UNLOCK();

    char mac[13], dev_id[32];
    get_device_identity(mac, sizeof(mac), dev_id, sizeof(dev_id));
    uint32_t uptime_sec = (uint32_t)(esp_timer_get_time() / 1000000ULL);

    char *buf = malloc(1024);
    if (!buf) { httpd_resp_send_500(req); return ESP_FAIL; }

    int len = snprintf(buf, 1024,
        "{\"wifi_sta\":{\"connected\":true,\"ssid\":\"EnergyGateway\",\"ip\":\"%s\",\"rssi\":-50},"
        "\"cloud\":{\"enabled\":false,\"connected\":false},"
        "\"mqtt\":{\"connected\":false},"
        "\"time\":\"12:00\",\"unixtime\":%lu,\"serial\":1,\"has_update\":false,\"mac\":\"%s\","
        "\"relays\":[{\"ison\":true,\"has_timer\":false,\"overpower\":false,\"is_valid\":true}],"
        "\"emeters\":["
        "{\"power\":%.2f,\"pf\":%.2f,\"current\":%.2f,\"voltage\":%.2f,\"is_valid\":true,\"total\":%.2f,\"total_returned\":%.2f},"
        "{\"power\":%.2f,\"pf\":%.2f,\"current\":%.2f,\"voltage\":%.2f,\"is_valid\":true,\"total\":%.2f,\"total_returned\":%.2f},"
        "{\"power\":%.2f,\"pf\":%.2f,\"current\":%.2f,\"voltage\":%.2f,\"is_valid\":true,\"total\":%.2f,\"total_returned\":%.2f}"
        "],"
        "\"total_power\":%.2f,\"fs_mounted\":true,\"uptime\":%lu}",
        eth_ip, (unsigned long)uptime_sec, mac,
        snap.a_act_power, snap.a_pf, snap.a_current, snap.a_voltage, snap.a_total_wh, snap.a_total_ret_wh,
        snap.b_act_power, snap.b_pf, snap.b_current, snap.b_voltage, snap.b_total_wh, snap.b_total_ret_wh,
        snap.c_act_power, snap.c_pf, snap.c_current, snap.c_voltage, snap.c_total_wh, snap.c_total_ret_wh,
        snap.total_act_power, (unsigned long)uptime_sec
    );

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, buf, len);
    free(buf);
    return ESP_OK;
}

static esp_err_t handler_gen1_settings_get(httpd_req_t *req)
{
    char mac[13], dev_id[32];
    get_device_identity(mac, sizeof(mac), dev_id, sizeof(dev_id));

    char buf[256];
    int len = snprintf(buf, sizeof(buf),
        "{\"device\":{\"type\":\"SHEM-3\",\"mac\":\"%s\",\"hostname\":\"shellyem3-%s\"},"
        "\"coiot\":{\"enabled\":true,\"update_period\":15}}",
        mac, mac);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, buf, len);
    return ESP_OK;
}

static esp_err_t handler_rpc_post(httpd_req_t *req)
{
    int total_len = req->content_len;
    if (total_len <= 0 || total_len > 1024) {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    char *body = malloc(total_len + 1);
    if (!body) { httpd_resp_send_500(req); return ESP_FAIL; }

    int cur = 0;
    while (cur < total_len) {
        int r = httpd_req_recv(req, body + cur, total_len - cur);
        if (r <= 0) { free(body); httpd_resp_send_500(req); return ESP_FAIL; }
        cur += r;
    }
    body[total_len] = '\0';

    cJSON *root = cJSON_Parse(body);
    free(body);
    if (!root) {
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, "{\"error\":{\"code\":-32700,\"message\":\"Parse error\"}}", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }

    cJSON *id_item = cJSON_GetObjectItemCaseSensitive(root, "id");
    int req_id = 0;
    bool has_id = false;
    if (cJSON_IsNumber(id_item)) {
        req_id = (int)id_item->valuedouble;
        has_id = true;
    }

    cJSON *method_item = cJSON_GetObjectItemCaseSensitive(root, "method");
    char method[64] = {0};
    if (cJSON_IsString(method_item) && method_item->valuestring) {
        strncpy(method, method_item->valuestring, sizeof(method) - 1);
    }
    cJSON_Delete(root);

    if (!has_id) {
        /* Unwrapped endpoints */
        if (strcmp(method, "EM.GetStatus") == 0) {
            return handler_em_get_status_get(req);
        } else if (strcmp(method, "EM.GetConfig") == 0) {
            return handler_em_get_config_get(req);
        } else if (strcmp(method, "EM.GetCTTypes") == 0) {
            return handler_em_get_ct_types_get(req);
        } else if (strcmp(method, "EM.SetConfig") == 0) {
            httpd_resp_set_type(req, "application/json");
            httpd_resp_send(req, "{\"restart_required\":false}", HTTPD_RESP_USE_STRLEN);
            return ESP_OK;
        } else if (strcmp(method, "EMData.GetStatus") == 0) {
            return handler_emdata_get_status_get(req);
        } else if (strcmp(method, "Shelly.GetDeviceInfo") == 0) {
            return handler_shelly_device_info_get(req);
        } else if (strcmp(method, "Shelly.GetConfig") == 0) {
            return handler_shelly_get_config_get(req);
        } else if (strcmp(method, "Shelly.GetStatus") == 0) {
            return handler_shelly_get_status_get(req);
        } else {
            httpd_resp_set_type(req, "application/json");
            httpd_resp_send(req, "{\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}", HTTPD_RESP_USE_STRLEN);
            return ESP_OK;
        }
    }

    /* JSON-RPC 2.0 enveloped responses */
    char mac[13], dev_id[32];
    get_device_identity(mac, sizeof(mac), dev_id, sizeof(dev_id));

    if (strcmp(method, "EM.GetStatus") == 0) {
        shelly_data_snapshot_t snap;
        if (!data_store_get_shelly_snapshot(&snap) || !snap.shelly_valid) {
            httpd_resp_set_status(req, "503 Service Unavailable");
            httpd_resp_set_type(req, "application/json");
            char err_buf[128];
            snprintf(err_buf, sizeof(err_buf), "{\"id\":%d,\"src\":\"%s\",\"error\":{\"code\":-32000,\"message\":\"Sensor data unavailable\"}}", req_id, dev_id);
            httpd_resp_send(req, err_buf, HTTPD_RESP_USE_STRLEN);
            return ESP_OK;
        }
        char *buf = malloc(1152);
        if (!buf) { httpd_resp_send_500(req); return ESP_FAIL; }
        int len = snprintf(buf, 1152,
            "{\"id\":%d,\"src\":\"%s\",\"result\":{"
            "\"id\":0,\"ct_state\":1,"
            "\"a_current\":%.4f,\"a_voltage\":%.4f,\"a_act_power\":%.4f,\"a_aprt_power\":%.4f,\"a_pf\":%.4f,\"a_freq\":%.4f,"
            "\"b_current\":%.4f,\"b_voltage\":%.4f,\"b_act_power\":%.4f,\"b_aprt_power\":%.4f,\"b_pf\":%.4f,\"b_freq\":%.4f,"
            "\"c_current\":%.4f,\"c_voltage\":%.4f,\"c_act_power\":%.4f,\"c_aprt_power\":%.4f,\"c_pf\":%.4f,\"c_freq\":%.4f,"
            "\"n_current\":null,\"total_current\":%.4f,\"total_act_power\":%.4f,\"total_aprt_power\":%.4f,\"user_calibrated_phase\":[]}}",
            req_id, dev_id,
            snap.a_current, snap.a_voltage, snap.a_act_power, snap.a_aprt_power, snap.a_pf, snap.a_freq,
            snap.b_current, snap.b_voltage, snap.b_act_power, snap.b_aprt_power, snap.b_pf, snap.b_freq,
            snap.c_current, snap.c_voltage, snap.c_act_power, snap.c_aprt_power, snap.c_pf, snap.c_freq,
            snap.total_current, snap.total_act_power, snap.total_aprt_power
        );
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, buf, len);
        free(buf);
        return ESP_OK;
    } else if (strcmp(method, "EM.GetConfig") == 0) {
        char buf[256];
        int len = snprintf(buf, sizeof(buf),
            "{\"id\":%d,\"src\":\"%s\",\"result\":{\"id\":0,\"name\":null,\"blink_mode_selector\":\"all\",\"phase_selector\":\"all\",\"monitor_phase_sequence\":true,\"ct_type\":\"120A\",\"reverse\":{}}}",
            req_id, dev_id);
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, buf, len);
        return ESP_OK;
    } else if (strcmp(method, "EM.GetCTTypes") == 0) {
        char buf[128];
        int len = snprintf(buf, sizeof(buf),
            "{\"id\":%d,\"src\":\"%s\",\"result\":[\"120A\",\"400A\",\"50A\"]}",
            req_id, dev_id);
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, buf, len);
        return ESP_OK;
    } else if (strcmp(method, "EM.SetConfig") == 0) {
        char buf[128];
        int len = snprintf(buf, sizeof(buf),
            "{\"id\":%d,\"src\":\"%s\",\"result\":{\"restart_required\":false}}",
            req_id, dev_id);
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, buf, len);
        return ESP_OK;
    } else if (strcmp(method, "Shelly.GetDeviceInfo") == 0) {
        char buf[384];
        int len = snprintf(buf, sizeof(buf),
            "{\"id\":%d,\"src\":\"%s\",\"result\":{\"id\":\"%s\",\"mac\":\"%s\",\"model\":\"SPEM-003CEBEU\",\"gen\":2,\"fw_id\":\"20240101-120000/v1.4.0-esp32gw\",\"ver\":\"1.4.0\",\"app\":\"Pro3EM\",\"profile\":\"em\"}}",
            req_id, dev_id, dev_id, mac);
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, buf, len);
        return ESP_OK;
    } else if (strcmp(method, "Shelly.GetConfig") == 0) {
        char buf[384];
        int len = snprintf(buf, sizeof(buf),
            "{\"id\":%d,\"src\":\"%s\",\"result\":{\"em:0\":{\"id\":0,\"name\":null,\"blink_mode_selector\":\"all\",\"phase_selector\":\"all\",\"monitor_phase_sequence\":true,\"ct_type\":\"120A\"},\"em\":{\"id\":0,\"phase_selector\":\"all\",\"ct_type\":\"120A\",\"ct_types\":[\"120A\",\"120A\",\"120A\"]}}}",
            req_id, dev_id);
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, buf, len);
        return ESP_OK;
    } else {
        char buf[128];
        int len = snprintf(buf, sizeof(buf), "{\"id\":%d,\"src\":\"%s\",\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}", req_id, dev_id);
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, buf, len);
        return ESP_OK;
    }
}

/* ------------------------------------------------------------------ */
/*  URI Table & Server Initialization                                   */
/* ------------------------------------------------------------------ */

static const httpd_uri_t uri_root = { .uri = "/", .method = HTTP_GET, .handler = handler_root_get };
static const httpd_uri_t uri_cfg_get = { .uri = "/config", .method = HTTP_GET, .handler = handler_config_get };
static const httpd_uri_t uri_cfg_post = { .uri = "/config", .method = HTTP_POST, .handler = handler_config_post };
static const httpd_uri_t uri_ota_post = { .uri = "/update", .method = HTTP_POST, .handler = handler_update_post };
static const httpd_uri_t uri_status_get = { .uri = "/api/status", .method = HTTP_GET, .handler = handler_api_status_get };
static const httpd_uri_t uri_writes_get = { .uri = "/api/writes", .method = HTTP_GET, .handler = handler_api_writes_get };
static const httpd_uri_t uri_reset_post = { .uri = "/api/reset", .method = HTTP_POST, .handler = handler_api_reset_post };
static const httpd_uri_t uri_shelly = { .uri = "/shelly", .method = HTTP_GET, .handler = handler_shelly_device_info_get };
static const httpd_uri_t uri_rpc_dev = { .uri = "/rpc/Shelly.GetDeviceInfo", .method = HTTP_GET, .handler = handler_shelly_device_info_get };
static const httpd_uri_t uri_rpc_cfg = { .uri = "/rpc/Shelly.GetConfig", .method = HTTP_GET, .handler = handler_shelly_get_config_get };
static const httpd_uri_t uri_rpc_em = { .uri = "/rpc/EM.GetStatus", .method = HTTP_GET, .handler = handler_em_get_status_get };
static const httpd_uri_t uri_rpc_em_cfg = { .uri = "/rpc/EM.GetConfig", .method = HTTP_GET, .handler = handler_em_get_config_get };
static const httpd_uri_t uri_rpc_em_ct  = { .uri = "/rpc/EM.GetCTTypes", .method = HTTP_GET, .handler = handler_em_get_ct_types_get };
static const httpd_uri_t uri_rpc_emd = { .uri = "/rpc/EMData.GetStatus", .method = HTTP_GET, .handler = handler_emdata_get_status_get };
static const httpd_uri_t uri_rpc_shs = { .uri = "/rpc/Shelly.GetStatus", .method = HTTP_GET, .handler = handler_shelly_get_status_get };
static const httpd_uri_t uri_rpc_post = { .uri = "/rpc", .method = HTTP_POST, .handler = handler_rpc_post };
static const httpd_uri_t uri_gen1_status = { .uri = "/status", .method = HTTP_GET, .handler = handler_gen1_status_get };
static const httpd_uri_t uri_gen1_settings = { .uri = "/settings", .method = HTTP_GET, .handler = handler_gen1_settings_get };

esp_err_t http_server_start(void)
{
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();

    /* Sockets & LRU purge: auto-close idle keep-alive connections */
    config.max_open_sockets = 7;
    config.lru_purge_enable = true;
    config.recv_wait_timeout = 5;
    config.send_wait_timeout = 5;
    config.max_uri_handlers = 24;
    config.stack_size = 10240;
    config.uri_match_fn = httpd_uri_match_wildcard;

    esp_err_t ret = httpd_start(&server, &config);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "httpd_start failed: %s", esp_err_to_name(ret));
        return ret;
    }

    httpd_register_uri_handler(server, &uri_root);
    httpd_register_uri_handler(server, &uri_cfg_get);
    httpd_register_uri_handler(server, &uri_cfg_post);
    httpd_register_uri_handler(server, &uri_ota_post);
    httpd_register_uri_handler(server, &uri_status_get);
    httpd_register_uri_handler(server, &uri_writes_get);
    httpd_register_uri_handler(server, &uri_reset_post);
    httpd_register_uri_handler(server, &uri_shelly);
    httpd_register_uri_handler(server, &uri_rpc_dev);
    httpd_register_uri_handler(server, &uri_rpc_cfg);
    httpd_register_uri_handler(server, &uri_rpc_em);
    httpd_register_uri_handler(server, &uri_rpc_em_cfg);
    httpd_register_uri_handler(server, &uri_rpc_em_ct);
    httpd_register_uri_handler(server, &uri_rpc_emd);
    httpd_register_uri_handler(server, &uri_rpc_shs);
    httpd_register_uri_handler(server, &uri_rpc_post);
    httpd_register_uri_handler(server, &uri_gen1_status);
    httpd_register_uri_handler(server, &uri_gen1_settings);

    ESP_LOGI(TAG, "HTTP server started on port %d (Auth & CSRF enabled)", config.server_port);
    return ESP_OK;
}

