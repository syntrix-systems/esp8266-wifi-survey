/*
 * ESP-01 WiFi Survey  v1.0.0
 *
 * Passively listens (802.11 promiscuous mode, no transmitting, no deauth, no
 * injection) while hopping across channels and records:
 *   - every access point heard (SSID, BSSID, channel, RSSI, security)
 *   - every client device heard (MAC, RSSI, which AP/BSSID it is talking to,
 *     roam count, SSID it is probing for)
 *
 * Setup: first boot (or no saved network) -> open AP "WifiSurvey-xxxxxx" with a
 * captive portal. Pick your network, save, device reboots and joins it.
 * Hold GPIO0 low for 5 s while running to get the setup portal back.
 *
 * The ESP8266 has ONE radio. It cannot sniff other channels and stay connected
 * at the same time, so the firmware works in duty cycles:
 *    [ sweep all channels ~4 s ] -> [ reconnect ] -> [ serve / push ] -> wait
 * Data accumulates across sweeps and is kept in RAM for "keep" seconds.
 */

#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <ESP8266mDNS.h>
#include <DNSServer.h>
#include <EEPROM.h>
#include <time.h>
extern "C" {
#include <user_interface.h>
}

#define FW_VERSION "1.0.0"
#define MAX_STA 128
#define MAX_AP 48
#define CFG_MAGIC 0x57534602UL
#define BTN_PIN 0

// ───────────────────────── config (EEPROM) ─────────────────────────
struct Config {
  uint32_t magic;
  char ssid[33];
  char pass[65];
  char host[24];
  char secret[17];   // setup-AP WPA2 password (>=8 chars) and admin password for /config
  char ntp[40];
  char push[96];     // optional http://host[:port]/path to POST JSON to after each sweep
  uint8_t mode;      // 0 = join WiFi, 1 = standalone AP (dashboard on 192.168.4.1)
  uint8_t maxCh;     // 11, 13 or 14
  uint16_t dwellMs;  // per-channel listen time
  uint16_t intervalS;// idle time between sweeps
  uint32_t keepS;    // forget devices not heard for this long
};
static Config cfg;

static void cfgDefaults() {
  memset(&cfg, 0, sizeof(cfg));
  cfg.magic = CFG_MAGIC;
  strcpy(cfg.host, "wifisurvey");
  strcpy(cfg.ntp, "pool.ntp.org");
  cfg.mode = 0;
  cfg.maxCh = 13;
  cfg.dwellMs = 300;
  cfg.intervalS = 30;
  cfg.keepS = 900;
}
static void cfgLoad() {
  EEPROM.begin(512);
  EEPROM.get(0, cfg);
  if (cfg.magic != CFG_MAGIC) cfgDefaults();
  cfg.ssid[32] = cfg.pass[64] = cfg.host[23] = cfg.secret[16] = cfg.ntp[39] = cfg.push[95] = 0;
}
static void cfgSave() {
  EEPROM.put(0, cfg);
  EEPROM.commit();
}

// ───────────────────────── survey tables ─────────────────────────
struct Ap {
  uint8_t bssid[6];
  bool used, hidden;
  uint8_t ch, sec;       // sec: 255 unknown, 0 open, 1 secured, 2 WPA, 3 WPA2/3
  int8_t rssi;
  char ssid[33];
  uint32_t first, last, frames;
};
struct Sta {
  uint8_t mac[6];
  uint8_t bssid[6];
  bool used, assoc;
  int8_t rssi;
  uint8_t ch, roams;
  char probe[24];
  uint32_t first, last, frames;
};
static Ap aps[MAX_AP];
static Sta stas[MAX_STA];

static uint32_t sweepCount = 0, lastSweepMs = 0, lastSweepDur = 0;
static int8_t pushState = -1;  // -1 off, 0 failed, 1 ok

static inline int8_t IRAM_ATTR smooth(int8_t old, int8_t nw) {
  return old == 0 ? nw : (int8_t)((old * 3 + nw) / 4);
}

static Ap* IRAM_ATTR apFind(const uint8_t* b, bool create) {
  Ap* freeS = nullptr;
  Ap* old = nullptr;
  for (int i = 0; i < MAX_AP; i++) {
    Ap* a = &aps[i];
    if (a->used) {
      if (!memcmp(a->bssid, b, 6)) return a;
      if (!old || (int32_t)(a->last - old->last) < 0) old = a;
    } else if (!freeS) freeS = a;
  }
  if (!create) return nullptr;
  Ap* a = freeS ? freeS : old;
  memset(a, 0, sizeof(Ap));
  memcpy(a->bssid, b, 6);
  a->used = true;
  a->sec = 255;
  a->first = a->last = millis();
  return a;
}

static Sta* IRAM_ATTR staFind(const uint8_t* m, bool create) {
  Sta* freeS = nullptr;
  Sta* old = nullptr;
  for (int i = 0; i < MAX_STA; i++) {
    Sta* s = &stas[i];
    if (s->used) {
      if (!memcmp(s->mac, m, 6)) return s;
      if (!old || (int32_t)(s->last - old->last) < 0) old = s;
    } else if (!freeS) freeS = s;
  }
  if (!create) return nullptr;
  Sta* s = freeS ? freeS : old;
  memset(s, 0, sizeof(Sta));
  memcpy(s->mac, m, 6);
  s->used = true;
  s->first = s->last = millis();
  return s;
}

static void IRAM_ATTR secUp(Ap* a, uint8_t v) {
  if (a->sec == 255 || v > a->sec) a->sec = v;
}

// ie/n: information elements following the fixed fields of a beacon / probe response
static void IRAM_ATTR noteAp(const uint8_t* bssid, int8_t rssi, uint8_t ch,
                             const uint8_t* ie, int n, bool privacy) {
  if (bssid[0] & 1) return;
  Ap* a = apFind(bssid, true);
  a->last = millis();
  a->frames++;
  if (rssi) a->rssi = smooth(a->rssi, rssi);
  if (ch && !a->ch) a->ch = ch;
  if (!ie) return;
  if (ch) a->ch = ch;
  secUp(a, privacy ? 1 : 0);
  for (int i = 0; i + 2 <= n;) {
    uint8_t t = ie[i], l = ie[i + 1];
    if (i + 2 + l > n) break;
    const uint8_t* v = ie + i + 2;
    if (t == 0) {
      if (l == 0 || v[0] == 0) a->hidden = true;
      else if (l <= 32) { memcpy(a->ssid, v, l); a->ssid[l] = 0; }
    } else if (t == 3 && l >= 1 && v[0] >= 1 && v[0] <= 14) {
      a->ch = v[0];
    } else if (t == 48) {
      secUp(a, 3);
    } else if (t == 221 && l >= 4 && v[0] == 0x00 && v[1] == 0x50 && v[2] == 0xF2 && v[3] == 1) {
      secUp(a, 2);
    }
    i += 2 + l;
  }
}

// rssi==0 -> frame was sent by the AP (its signal says nothing about the station)
static void IRAM_ATTR noteSta(const uint8_t* mac, const uint8_t* bssid, int8_t rssi, uint8_t ch,
                              const uint8_t* probe, int plen) {
  if (mac[0] & 1) return;
  Sta* s = staFind(mac, true);
  s->last = millis();
  s->frames++;
  if (rssi) s->rssi = smooth(s->rssi, rssi);
  if (ch) s->ch = ch;
  if (bssid && !(bssid[0] & 1)) {
    if (s->assoc && memcmp(s->bssid, bssid, 6)) {
      if (s->roams < 255) s->roams++;
    }
    memcpy(s->bssid, bssid, 6);
    s->assoc = true;
  }
  if (probe && plen > 0 && probe[0]) {
    int n = plen < 23 ? plen : 23;
    memcpy(s->probe, probe, n);
    s->probe[n] = 0;
  }
}

// ESP8266 sniffer callback. len==12: RxControl only. len==128: management frame
// (112 bytes of frame). Anything else: data/control, first 36 bytes of header.
static void IRAM_ATTR onFrame(uint8_t* buf, uint16_t len) {
  if (len <= 12) return;
  int8_t rssi = (int8_t)buf[0];
  uint8_t ch = buf[10] & 0x0F;
  const uint8_t* f = buf + 12;
  int avail = (len == 128) ? 112 : 36;
  uint8_t fc0 = f[0], fc1 = f[1];
  uint8_t type = (fc0 >> 2) & 3, sub = fc0 >> 4;
  const uint8_t *a1 = f + 4, *a2 = f + 10, *a3 = f + 16;

  if (type == 0) {  // management
    switch (sub) {
      case 8:  // beacon
      case 5:  // probe response
        if (len == 128) noteAp(a3, rssi, ch, f + 36, avail - 36, (f[34] & 0x10) != 0);
        break;
      case 4: {  // probe request: a2 = station
        if (a2[0] & 1) break;
        const uint8_t* ie = f + 24;
        int n = avail - 24;
        if (n >= 2 && ie[0] == 0 && ie[1] > 0 && ie[1] + 2 <= n) noteSta(a2, nullptr, rssi, ch, ie + 2, ie[1]);
        else noteSta(a2, nullptr, rssi, ch, nullptr, 0);
        break;
      }
      case 0:  // (re)association request: station is trying, link not confirmed yet
      case 2:
        noteSta(a2, nullptr, rssi, ch, nullptr, 0);
        break;
      case 1:  // (re)association response: a1 = station, a2 = AP; status 0 = success
      case 3:
        if (len == 128 && f[26] == 0 && f[27] == 0) {
          noteAp(a2, rssi, ch, nullptr, 0, false);
          noteSta(a1, a2, 0, ch, nullptr, 0);
        }
        break;
    }
  } else if (type == 1) {  // control
    if (sub == 10) {       // PS-Poll: a1 = BSSID, a2 = station
      noteAp(a1, 0, ch, nullptr, 0, false);
      noteSta(a2, a1, rssi, ch, nullptr, 0);
    }
  } else if (type == 2) {  // data
    bool to = fc1 & 1, from = (fc1 & 2) != 0;
    if (to && !from) {         // station -> AP
      noteAp(a1, 0, ch, nullptr, 0, false);
      noteSta(a2, a1, rssi, ch, nullptr, 0);
    } else if (!to && from) {  // AP -> station
      noteAp(a2, rssi, ch, nullptr, 0, false);
      noteSta(a1, a2, 0, ch, nullptr, 0);
    }
  }
}

static void purge() {
  uint32_t now = millis(), keep = cfg.keepS * 1000UL;
  for (int i = 0; i < MAX_AP; i++) if (aps[i].used && now - aps[i].last > keep) aps[i].used = false;
  for (int i = 0; i < MAX_STA; i++) if (stas[i].used && now - stas[i].last > keep) stas[i].used = false;
}

// ───────────────────────── output helpers ─────────────────────────
class BufSink : public Print {
 public:
  using Print::write;
  size_t write(uint8_t c) override {
    b[n++] = c;
    if (n == sizeof(b)) flushBuf();
    return 1;
  }
  size_t write(const uint8_t* d, size_t l) override {
    for (size_t i = 0; i < l; i++) write(d[i]);
    return l;
  }
  void flushBuf() {
    if (n) { out(b, n); n = 0; }
  }
 protected:
  virtual void out(const uint8_t* d, size_t l) = 0;
 private:
  uint8_t b[384];
  size_t n = 0;
};

static ESP8266WebServer server(80);
static DNSServer dns;

class WebSink : public BufSink {
 protected:
  void out(const uint8_t* d, size_t l) override { server.sendContent((const char*)d, l); }
};
class ClientSink : public BufSink {
 public:
  explicit ClientSink(WiFiClient& cl) : c(cl) {}
 protected:
  void out(const uint8_t* d, size_t l) override {
    c.printf("%X\r\n", (unsigned)l);
    c.write(d, l);
    c.print("\r\n");
  }
 private:
  WiFiClient& c;
};

static void macStr(const uint8_t* m, char* o) {
  snprintf(o, 18, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}
static void pc(Print& p, char c) { p.write((uint8_t)c); }
static void pb(Print& p, bool v) { p.print(v ? F("true") : F("false")); }

static void jstr(Print& p, const char* s) {
  pc(p, '"');
  for (; *s; s++) {
    unsigned char c = *s;
    if (c == '"' || c == '\\') { pc(p, '\\'); pc(p, c); }
    else if (c < 0x20) { char b[8]; snprintf(b, sizeof(b), "\\u%04x", c); p.print(b); }
    else pc(p, c);
  }
  pc(p, '"');
}
static void cstr(Print& p, const char* s) {  // CSV field
  pc(p, '"');
  for (; *s; s++) { if (*s == '"') pc(p, '"'); pc(p, *s); }
  pc(p, '"');
}
static const char* secStr(uint8_t s) {
  switch (s) { case 0: return "open"; case 1: return "secured"; case 2: return "wpa"; case 3: return "wpa2/3"; }
  return "unknown";
}
static uint32_t ageS(uint32_t ms) { return (millis() - ms) / 1000; }

static void writeTimes(Print& p, uint32_t first, uint32_t last) {
  time_t now = time(nullptr);
  bool ok = now > 1700000000;
  uint32_t fa = ageS(first), la = ageS(last);
  p.print(F(",\"first_age_s\":")); p.print(fa);
  p.print(F(",\"age_s\":")); p.print(la);
  p.print(F(",\"first_seen\":"));
  if (ok) p.print((unsigned long)(now - fa)); else p.print(F("null"));
  p.print(F(",\"last_seen\":"));
  if (ok) p.print((unsigned long)(now - la)); else p.print(F("null"));
}

static int clientsOf(const uint8_t* bssid) {
  int n = 0;
  for (int i = 0; i < MAX_STA; i++)
    if (stas[i].used && stas[i].assoc && !memcmp(stas[i].bssid, bssid, 6)) n++;
  return n;
}
static void counts(int& nAp, int& nSta, int& nAssoc) {
  nAp = nSta = nAssoc = 0;
  for (int i = 0; i < MAX_AP; i++) if (aps[i].used) nAp++;
  for (int i = 0; i < MAX_STA; i++) if (stas[i].used) { nSta++; if (stas[i].assoc) nAssoc++; }
}

static bool configMode = false;
static String apName;

static void jsonDevice(Print& p) {
  int na, ns, nas;
  counts(na, ns, nas);
  time_t now = time(nullptr);
  p.print(F("{\"id\":")); jstr(p, apName.c_str());
  p.print(F(",\"fw\":\"" FW_VERSION "\",\"mode\":\""));
  p.print(cfg.mode ? F("ap") : F("sta"));
  p.print(F("\",\"ip\":\""));
  p.print((cfg.mode ? WiFi.softAPIP() : WiFi.localIP()).toString());
  p.print(F("\",\"uptime_s\":")); p.print((unsigned long)(millis() / 1000));
  p.print(F(",\"epoch\":"));
  if (now > 1700000000) p.print((unsigned long)now); else p.print(F("null"));
  p.print(F(",\"sweeps\":")); p.print((unsigned long)sweepCount);
  p.print(F(",\"last_sweep_age_s\":"));
  if (sweepCount) p.print((unsigned long)ageS(lastSweepMs)); else p.print(F("null"));
  p.print(F(",\"sweep_ms\":")); p.print((unsigned long)lastSweepDur);
  p.print(F(",\"ap_count\":")); p.print(na);
  p.print(F(",\"station_count\":")); p.print(ns);
  p.print(F(",\"associated_count\":")); p.print(nas);
  p.print(F(",\"push\":"));
  if (pushState < 0) p.print(F("null")); else p.print(pushState ? F("\"ok\"") : F("\"failed\""));
  p.print(F(",\"heap\":")); p.print((unsigned long)ESP.getFreeHeap());
  pc(p, '}');
}

static void jsonAps(Print& p) {
  pc(p, '[');
  bool first = true;
  char m[18];
  for (int i = 0; i < MAX_AP; i++) {
    const Ap& a = aps[i];
    if (!a.used) continue;
    if (!first) pc(p, ',');
    first = false;
    macStr(a.bssid, m);
    p.print(F("{\"bssid\":\"")); p.print(m);
    p.print(F("\",\"ssid\":"));
    if (a.ssid[0]) jstr(p, a.ssid); else p.print(F("null"));
    p.print(F(",\"hidden\":")); pb(p, a.hidden);
    p.print(F(",\"channel\":")); p.print((int)a.ch);
    p.print(F(",\"rssi\":"));
    if (a.rssi) p.print((int)a.rssi); else p.print(F("null"));
    p.print(F(",\"security\":\"")); p.print(secStr(a.sec));
    p.print(F("\",\"clients\":")); p.print(clientsOf(a.bssid));
    p.print(F(",\"frames\":")); p.print((unsigned long)a.frames);
    writeTimes(p, a.first, a.last);
    pc(p, '}');
  }
  pc(p, ']');
}

static void jsonStations(Print& p) {
  pc(p, '[');
  bool first = true;
  char m[18];
  for (int i = 0; i < MAX_STA; i++) {
    const Sta& s = stas[i];
    if (!s.used) continue;
    if (!first) pc(p, ',');
    first = false;
    Ap* ap = s.assoc ? apFind(s.bssid, false) : nullptr;
    macStr(s.mac, m);
    p.print(F("{\"mac\":\"")); p.print(m);
    p.print(F("\",\"randomized\":")); pb(p, (s.mac[0] & 2) != 0);
    p.print(F(",\"associated\":")); pb(p, s.assoc);
    p.print(F(",\"bssid\":"));
    if (s.assoc) { macStr(s.bssid, m); pc(p, '"'); p.print(m); pc(p, '"'); } else p.print(F("null"));
    p.print(F(",\"ssid\":"));
    if (ap && ap->ssid[0]) jstr(p, ap->ssid); else p.print(F("null"));
    p.print(F(",\"rssi\":"));
    if (s.rssi) p.print((int)s.rssi); else p.print(F("null"));
    p.print(F(",\"channel\":")); p.print((int)s.ch);
    p.print(F(",\"roams\":")); p.print((int)s.roams);
    p.print(F(",\"probe\":"));
    if (s.probe[0]) jstr(p, s.probe); else p.print(F("null"));
    p.print(F(",\"frames\":")); p.print((unsigned long)s.frames);
    writeTimes(p, s.first, s.last);
    pc(p, '}');
  }
  pc(p, ']');
}

static void jsonAll(Print& p) {
  p.print(F("{\"device\":")); jsonDevice(p);
  p.print(F(",\"aps\":")); jsonAps(p);
  p.print(F(",\"stations\":")); jsonStations(p);
  pc(p, '}');
}

static void jsonSummary(Print& p) {
  int na, ns, nas;
  counts(na, ns, nas);
  p.print(F("{\"aps\":")); p.print(na);
  p.print(F(",\"stations\":")); p.print(ns);
  p.print(F(",\"associated\":")); p.print(nas);
  p.print(F(",\"unassociated\":")); p.print(ns - nas);
  p.print(F(",\"sweeps\":")); p.print((unsigned long)sweepCount);
  p.print(F(",\"last_sweep_age_s\":"));
  if (sweepCount) p.print((unsigned long)ageS(lastSweepMs)); else p.print(-1);
  p.print(F(",\"uptime_s\":")); p.print((unsigned long)(millis() / 1000));
  p.print(F(",\"heap\":")); p.print((unsigned long)ESP.getFreeHeap());
  pc(p, '}');
}

static void csvStations(Print& p) {
  p.print(F("mac,randomized,associated,bssid,ssid,rssi,channel,roams,probe,frames,first_age_s,age_s\n"));
  char m[18];
  for (int i = 0; i < MAX_STA; i++) {
    const Sta& s = stas[i];
    if (!s.used) continue;
    Ap* ap = s.assoc ? apFind(s.bssid, false) : nullptr;
    macStr(s.mac, m); p.print(m);
    pc(p, ','); p.print((s.mac[0] & 2) ? 1 : 0);
    pc(p, ','); p.print(s.assoc ? 1 : 0);
    pc(p, ',');
    if (s.assoc) { macStr(s.bssid, m); p.print(m); }
    pc(p, ','); if (ap && ap->ssid[0]) cstr(p, ap->ssid);
    pc(p, ','); if (s.rssi) p.print((int)s.rssi);
    pc(p, ','); p.print((int)s.ch);
    pc(p, ','); p.print((int)s.roams);
    pc(p, ','); if (s.probe[0]) cstr(p, s.probe);
    pc(p, ','); p.print((unsigned long)s.frames);
    pc(p, ','); p.print((unsigned long)ageS(s.first));
    pc(p, ','); p.print((unsigned long)ageS(s.last));
    pc(p, '\n');
  }
}

static void csvAps(Print& p) {
  p.print(F("bssid,ssid,hidden,channel,rssi,security,clients,frames,first_age_s,age_s\n"));
  char m[18];
  for (int i = 0; i < MAX_AP; i++) {
    const Ap& a = aps[i];
    if (!a.used) continue;
    macStr(a.bssid, m); p.print(m);
    pc(p, ','); if (a.ssid[0]) cstr(p, a.ssid);
    pc(p, ','); p.print(a.hidden ? 1 : 0);
    pc(p, ','); p.print((int)a.ch);
    pc(p, ','); if (a.rssi) p.print((int)a.rssi);
    pc(p, ','); p.print(secStr(a.sec));
    pc(p, ','); p.print(clientsOf(a.bssid));
    pc(p, ','); p.print((unsigned long)a.frames);
    pc(p, ','); p.print((unsigned long)ageS(a.first));
    pc(p, ','); p.print((unsigned long)ageS(a.last));
    pc(p, '\n');
  }
}

// ───────────────────────── web UI ─────────────────────────
static const char DASH[] PROGMEM = R"HTML(<!doctype html><html lang=en><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>WiFi Survey</title>
<style>
:root{--bg:#0e1216;--fg:#e8eef4;--mut:#8a97a5;--card:#161c22;--ln:#26303a;--ac:#4cc2ff;--ok:#3ecf8e;--wr:#f5a524;--bd:#ff6369}
@media(prefers-color-scheme:light){:root{--bg:#f5f7fa;--fg:#1c2530;--mut:#637080;--card:#fff;--ln:#d9e0e7;--ac:#0a6cc2}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.4 system-ui,sans-serif}
header{display:flex;flex-wrap:wrap;gap:8px 12px;align-items:center;padding:12px 16px;border-bottom:1px solid var(--ln)}
h1{font-size:16px;margin:0;flex:1;min-width:120px}
main{padding:12px 16px;max-width:1100px;margin:auto}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(105px,1fr));gap:8px;margin-bottom:12px}
.c{background:var(--card);border:1px solid var(--ln);border-radius:8px;padding:8px 10px}
.c b{display:block;font-size:20px}.c span{color:var(--mut);font-size:12px}
h2{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);margin:18px 0 6px}
.w{overflow-x:auto;border:1px solid var(--ln);border-radius:8px;background:var(--card)}
table{border-collapse:collapse;width:100%;white-space:nowrap}
th,td{padding:6px 10px;text-align:left;border-bottom:1px solid var(--ln)}
th{color:var(--mut);font-weight:500;font-size:12px}tr:last-child td{border:0}
tr.s{cursor:pointer}tr.s:hover,tr.on{background:rgba(76,194,255,.12)}
.m{font-family:ui-monospace,monospace;font-size:12px}
.t{display:inline-block;padding:0 6px;border-radius:9px;border:1px solid var(--ln);font-size:11px;color:var(--mut)}
.bar{display:inline-block;width:44px;height:6px;background:var(--ln);border-radius:3px;vertical-align:middle;margin-right:6px;overflow:hidden}
.bar i{display:block;height:100%}
.tools{display:flex;flex-wrap:wrap;gap:8px;margin:6px 0}
input,select{font:inherit;color:inherit;background:var(--card);border:1px solid var(--ln);border-radius:6px;padding:4px 8px}
a.b{color:inherit;border:1px solid var(--ln);border-radius:6px;padding:4px 10px;text-decoration:none;background:var(--card)}
#st{color:var(--mut);font-size:12px}
</style>
<header><h1>WiFi Survey</h1><span id=st>connecting…</span>
<a class=b href=/export.json>JSON</a><a class=b href=/export.csv>Devices CSV</a><a class=b href="/export.csv?t=aps">APs CSV</a><a class=b href=/config>Settings</a></header>
<main>
<div class=cards id=cards></div>
<h2>Access points <small id=sel></small></h2><div class=w><table id=ap></table></div>
<h2>Devices</h2>
<div class=tools><input id=q placeholder="filter: mac / ssid / probe">
<select id=f><option value=all>all<option value=a>associated<option value=u>not associated<option value=r>randomized MAC</select></div>
<div class=w><table id=sta></table></div>
</main>
<script>
let D=null,sel='';
const $=s=>document.querySelector(s),
esc=s=>String(s??'').replace(/[&<>"']/g,c=>'&#'+c.charCodeAt(0)+';'),
age=s=>s<90?s+'s':s<5400?Math.round(s/60)+'m':Math.round(s/3600)+'h',
bar=r=>{if(r==null)return'–';const p=Math.max(0,Math.min(100,(r+95)*100/55)),c=p>60?'var(--ok)':p>30?'var(--wr)':'var(--bd)';return`<span class=bar><i style="width:${p}%;background:${c}"></i></span>${r}`},
nm=a=>a.ssid?esc(a.ssid):a.hidden?'<i>hidden</i>':'<i>unknown</i>',
rs=(a,b)=>(b.rssi??-999)-(a.rssi??-999);
function render(){
 const d=D.device;
 $('#cards').innerHTML=[['access points',D.aps.length],['devices',D.stations.length],['associated',D.stations.filter(s=>s.associated).length],['sweeps',d.sweeps],['uptime',age(d.uptime_s)],['free heap',(d.heap/1024|0)+'k']].map(([k,v])=>`<div class=c><b>${v}</b><span>${k}</span></div>`).join('');
 $('#ap').innerHTML='<tr><th>SSID<th>BSSID<th>Ch<th>Signal<th>Security<th>Clients<th>Seen</tr>'+[...D.aps].sort(rs).map(a=>`<tr class="s${sel==a.bssid?' on':''}" data-b="${a.bssid}"><td>${nm(a)}<td class=m>${a.bssid}<td>${a.channel||''}<td>${bar(a.rssi)}<td>${a.security}<td>${a.clients}<td>${age(a.age_s)}</tr>`).join('');
 $('#sel').textContent=sel?'· filtering devices by '+sel+' (click again to clear)':'· click a row to filter devices';
 const q=$('#q').value.toLowerCase(),f=$('#f').value;
 const ss=D.stations.filter(s=>(!sel||s.bssid==sel)&&(f=='all'||(f=='a'&&s.associated)||(f=='u'&&!s.associated)||(f=='r'&&s.randomized))&&(!q||[s.mac,s.ssid,s.probe,s.bssid].join(' ').toLowerCase().includes(q))).sort(rs);
 $('#sta').innerHTML='<tr><th>Device<th>Connected to<th>Signal<th>Ch<th>Roams<th>Probing for<th>Seen</tr>'+ss.map(s=>`<tr><td class=m>${s.mac}${s.randomized?' <span class=t>random</span>':''}<td>${s.associated?(s.ssid?esc(s.ssid)+' ':'')+'<span class=m>'+s.bssid+'</span>':'<span class=t>not associated</span>'}<td>${bar(s.rssi)}<td>${s.channel||''}<td>${s.roams||''}<td>${esc(s.probe)}<td>${age(s.age_s)}</tr>`).join('');
}
$('#ap').onclick=e=>{const r=e.target.closest('tr[data-b]');if(r){sel=sel==r.dataset.b?'':r.dataset.b;render()}};
$('#q').oninput=$('#f').onchange=()=>D&&render();
async function tick(){
 try{const r=await fetch('/api/data',{cache:'no-store'});D=await r.json();$('#st').textContent='updated '+new Date().toLocaleTimeString();render()}
 catch(e){$('#st').textContent='device busy sweeping – retrying…'}
 setTimeout(tick,5000)}
tick();
</script></html>)HTML";

static const char CFG_HEAD[] PROGMEM = R"HTML(<!doctype html><html><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>WiFi Survey setup</title>
<style>body{font:15px system-ui,sans-serif;max-width:460px;margin:0 auto;padding:16px;background:#0e1216;color:#e8eef4}
h1{font-size:18px}h2{font-size:13px;color:#8a97a5;text-transform:uppercase;letter-spacing:.06em;margin:22px 0 0}
label{display:block;margin:10px 0 2px;color:#8a97a5;font-size:12px}
input,select,button{width:100%;padding:9px;border-radius:6px;border:1px solid #33404c;background:#161c22;color:inherit;font:inherit;box-sizing:border-box}
button{background:#4cc2ff;color:#04121c;border:0;font-weight:600;margin-top:16px;cursor:pointer}
.n a{display:block;padding:7px 9px;border:1px solid #26303a;border-radius:6px;margin:3px 0;color:inherit;text-decoration:none}
p a{color:#4cc2ff}small{color:#8a97a5}</style>
<h1>WiFi Survey setup</h1><div class=n>)HTML";

struct Net { char ssid[33]; int8_t rssi; bool open; };
static Net nets[16];
static int nNets = -1;

static void scanNets() {
  int n = WiFi.scanNetworks(false, true);
  nNets = 0;
  for (int i = 0; i < n; i++) {
    String s = WiFi.SSID(i);
    if (!s.length() || s.length() > 32) continue;
    int dup = -1;
    for (int k = 0; k < nNets; k++) if (s == nets[k].ssid) dup = k;
    if (dup >= 0) { if (WiFi.RSSI(i) > nets[dup].rssi) nets[dup].rssi = WiFi.RSSI(i); continue; }
    if (nNets >= 16) continue;
    strlcpy(nets[nNets].ssid, s.c_str(), sizeof(nets[nNets].ssid));
    nets[nNets].rssi = WiFi.RSSI(i);
    nets[nNets].open = WiFi.encryptionType(i) == ENC_TYPE_NONE;
    nNets++;
  }
  WiFi.scanDelete();
}

static String he(const String& s) {
  String o;
  o.reserve(s.length() + 8);
  for (size_t i = 0; i < s.length(); i++) {
    char c = s[i];
    switch (c) {
      case '&': o += F("&amp;"); break;
      case '<': o += F("&lt;"); break;
      case '>': o += F("&gt;"); break;
      case '"': o += F("&quot;"); break;
      case '\'': o += F("&#39;"); break;
      default: o += c;
    }
  }
  return o;
}
static String fld(const char* label, const char* name, const String& val, const char* type = "text",
                  const char* extra = "") {
  String h = F("<label>");
  h += label;
  h += F("<input name=");
  h += name;
  h += F(" type=");
  h += type;
  h += F(" value=\"");
  h += he(val);
  h += F("\" ");
  h += extra;
  h += F("></label>");
  return h;
}

static bool authOk() {
  if (configMode || cfg.mode == 1 || !cfg.secret[0]) return true;
  if (server.authenticate("admin", cfg.secret)) return true;
  server.requestAuthentication();
  return false;
}

static void startPortal(bool hasCreds);

static void handleConfig() {
  if (!authOk()) return;
  if (server.hasArg("rescan") || nNets < 0) scanNets();
  server.sendHeader("Cache-Control", "no-store");
  server.setContentLength(CONTENT_LENGTH_UNKNOWN);
  server.send(200, "text/html", "");
  server.sendContent_P(CFG_HEAD);
  String h;
  for (int i = 0; i < nNets; i++) {
    h += F("<a href=# onclick=\"document.getElementsByName('ssid')[0].value=this.dataset.s;return false\" data-s=\"");
    h += he(nets[i].ssid);
    h += F("\">");
    h += he(nets[i].ssid);
    h += F(" <small>");
    h += nets[i].rssi;
    h += F(" dBm");
    h += nets[i].open ? F(" · open") : F(" · secured");
    h += F("</small></a>");
  }
  if (!nNets) h += F("<small>No networks found – type the name below.</small>");
  h += F("</div><p><a href=\"/config?rescan=1\">Rescan</a> · <a href=/>Dashboard</a></p>"
         "<form method=post action=/save><h2>Network to join</h2>");
  h += fld("WiFi name (SSID)", "ssid", cfg.ssid, "text", "maxlength=32 autocapitalize=off");
  h += fld("Password (leave empty to keep saved one)", "pass", "", "password", "maxlength=64");
  h += F("<h2>Survey</h2><label>Mode<select name=mode><option value=0");
  if (cfg.mode == 0) h += F(" selected");
  h += F(">Join the network above (dashboard on my LAN)</option><option value=1");
  if (cfg.mode == 1) h += F(" selected");
  h += F(">Standalone access point (dashboard on 192.168.4.1)</option></select></label>");
  h += F("<label>Channels to scan<select name=maxch>");
  const uint8_t chs[3] = {11, 13, 14};
  const char* cl[3] = {"1-11 (US)", "1-13 (EU / most of world)", "1-14 (Japan)"};
  for (int i = 0; i < 3; i++) {
    h += F("<option value=");
    h += chs[i];
    if (cfg.maxCh == chs[i]) h += F(" selected");
    h += '>';
    h += cl[i];
    h += F("</option>");
  }
  h += F("</select></label>");
  h += fld("Listen time per channel (ms, 50-2000)", "dwell", String(cfg.dwellMs), "number", "min=50 max=2000");
  h += fld("Pause between sweeps (s, 5-3600)", "interval", String(cfg.intervalS), "number", "min=5 max=3600");
  h += fld("Forget devices unseen for (s)", "keep", String(cfg.keepS), "number", "min=60 max=604800");
  h += F("<h2>Export</h2>");
  h += fld("Push JSON after every sweep to (http:// only, optional)", "push", cfg.push, "text",
           "maxlength=95 placeholder=http://192.168.1.10:8080/ingest");
  h += fld("NTP server (for real timestamps)", "ntp", cfg.ntp, "text", "maxlength=39");
  h += F("<h2>Device</h2>");
  h += fld("Hostname (mDNS: name.local)", "host", cfg.host, "text", "maxlength=23");
  h += fld("Admin password (setup AP WPA2 password, min 8 chars; empty = none)", "secret", cfg.secret, "password",
           "maxlength=16");
  h += F("<button>Save &amp; reboot</button></form>"
         "<form method=post action=/factory onsubmit=\"return confirm('Erase all settings?')\">"
         "<button style=\"background:#ff6369\">Factory reset</button></form></html>");
  server.sendContent(h);
  server.sendContent("");
}

static String cleanHost(String s) {
  s.toLowerCase();
  String o;
  for (size_t i = 0; i < s.length(); i++) {
    char c = s[i];
    if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') o += c;
  }
  return o.length() ? o : String("wifisurvey");
}

static void handleSave() {
  if (!authOk()) return;
  String ns = server.arg("ssid");
  bool same = ns == cfg.ssid;
  String np = server.arg("pass");
  strlcpy(cfg.ssid, ns.c_str(), sizeof(cfg.ssid));
  if (np.length() || !same) strlcpy(cfg.pass, np.c_str(), sizeof(cfg.pass));
  strlcpy(cfg.host, cleanHost(server.arg("host")).c_str(), sizeof(cfg.host));
  String sec = server.arg("secret");
  if (sec.length() && sec.length() < 8 && !configMode) sec = "";  // WPA2 needs >=8
  strlcpy(cfg.secret, sec.c_str(), sizeof(cfg.secret));
  strlcpy(cfg.ntp, server.arg("ntp").c_str(), sizeof(cfg.ntp));
  String pu = server.arg("push");
  pu.trim();
  strlcpy(cfg.push, pu.startsWith("http://") ? pu.c_str() : "", sizeof(cfg.push));
  cfg.mode = server.arg("mode").toInt() == 1 ? 1 : 0;
  int mc = server.arg("maxch").toInt();
  cfg.maxCh = (mc == 11 || mc == 14) ? mc : 13;
  cfg.dwellMs = constrain(server.arg("dwell").toInt(), 50, 2000);
  cfg.intervalS = constrain(server.arg("interval").toInt(), 5, 3600);
  cfg.keepS = constrain(server.arg("keep").toInt(), 60, 604800);
  if (cfg.mode == 0 && !cfg.ssid[0]) cfg.mode = 1;  // nothing to join -> standalone
  cfgSave();
  server.send(200, "text/html",
              F("<meta name=viewport content='width=device-width,initial-scale=1'>"
                "<body style='font:16px system-ui;background:#0e1216;color:#e8eef4;padding:24px'>"
                "<h3>Saved</h3>Rebooting… reconnect to your network and open the device again "
                "(<b>http://hostname.local</b> or its new IP)."));
  delay(500);
  ESP.restart();
}

static void handleFactory() {
  if (!authOk()) return;
  cfgDefaults();
  cfgSave();
  server.send(200, "text/html", F("<body style='font:16px system-ui;padding:24px'>Settings erased, rebooting…"));
  delay(500);
  ESP.restart();
}

static void cors() {
  server.sendHeader("Cache-Control", "no-store");
  server.sendHeader("Access-Control-Allow-Origin", "*");
}
static void streamOut(const char* ctype, const char* fname, void (*fn)(Print&)) {
  cors();
  if (fname) server.sendHeader("Content-Disposition", String("attachment; filename=\"") + fname + "\"");
  server.setContentLength(CONTENT_LENGTH_UNKNOWN);
  server.send(200, ctype, "");
  WebSink s;
  fn(s);
  s.flushBuf();
  server.sendContent("");
}

static void handleRoot() {
  if (configMode) {
    server.sendHeader("Location", "/config");
    server.send(302);
    return;
  }
  server.send_P(200, "text/html", DASH);
}

static void handleNotFound() {
  if (configMode) {  // captive portal: send everything to the setup page
    server.sendHeader("Location", String("http://") + WiFi.softAPIP().toString() + "/config");
    server.send(302);
    return;
  }
  server.send(404, "text/plain", "not found");
}

static void setupRoutes() {
  server.on("/", handleRoot);
  server.on("/config", handleConfig);
  server.on("/save", HTTP_POST, handleSave);
  server.on("/factory", HTTP_POST, handleFactory);
  server.on("/api/data", []() { streamOut("application/json", nullptr, jsonAll); });
  server.on("/api/aps", []() { streamOut("application/json", nullptr, jsonAps); });
  server.on("/api/stations", []() { streamOut("application/json", nullptr, jsonStations); });
  server.on("/api/summary", []() { streamOut("application/json", nullptr, jsonSummary); });
  server.on("/export.json", []() { streamOut("application/json", "wifi-survey.json", jsonAll); });
  server.on("/export.csv", []() {
    bool aps_ = server.arg("t") == "aps";
    streamOut("text/csv", aps_ ? "wifi-survey-aps.csv" : "wifi-survey-devices.csv", aps_ ? csvAps : csvStations);
  });
  server.on("/api/clear", HTTP_POST, []() {
    if (!authOk()) return;
    memset(aps, 0, sizeof(aps));
    memset(stas, 0, sizeof(stas));
    cors();
    server.send(200, "application/json", "{\"cleared\":true}");
  });
  server.onNotFound(handleNotFound);
}

// ───────────────────────── WiFi management ─────────────────────────
static uint8_t homeCh = 0, homeBssid[6];
static bool haveHome = false, timeConfigured = false;
static uint32_t portalStart = 0;
static bool portalHasCreds = false;

static void rememberHome() {
  homeCh = WiFi.channel();
  memcpy(homeBssid, WiFi.BSSID(), 6);
  haveHome = true;
}

static void startAP() {
  WiFi.mode(WIFI_AP_STA);
  const char* pw = strlen(cfg.secret) >= 8 ? cfg.secret : nullptr;
  WiFi.softAP(apName.c_str(), pw, 6);
}

static void startPortal(bool hasCreds) {
  configMode = true;
  portalHasCreds = hasCreds;
  portalStart = millis();
  WiFi.disconnect();
  startAP();
  delay(200);
  scanNets();
  dns.start(53, "*", WiFi.softAPIP());
  Serial.printf("\nSetup portal: join '%s' then open http://%s/\n", apName.c_str(), WiFi.softAPIP().toString().c_str());
}

static bool connectSta(uint32_t timeoutMs) {
  WiFi.mode(WIFI_STA);
  WiFi.hostname(cfg.host);
  WiFi.setAutoReconnect(true);
  WiFi.begin(cfg.ssid, cfg.pass);
  uint32_t t = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t < timeoutMs) delay(200);
  if (WiFi.status() != WL_CONNECTED) return false;
  rememberHome();
  return true;
}

static void reconnect() {
  WiFi.mode(WIFI_STA);
  if (haveHome) WiFi.begin(cfg.ssid, cfg.pass, homeCh, homeBssid);  // fast path: known channel + BSSID
  else WiFi.begin(cfg.ssid, cfg.pass);
  uint32_t t = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t < 7000) delay(100);
  if (WiFi.status() != WL_CONNECTED) {  // AP moved? full scan
    WiFi.begin(cfg.ssid, cfg.pass);
    t = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - t < 12000) delay(100);
  }
  if (WiFi.status() == WL_CONNECTED) {
    rememberHome();
    MDNS.notifyAPChange();
  }
}

// ───────────────────────── sweep + push ─────────────────────────
static void doSweep() {
  uint32_t t0 = millis();
  if (cfg.mode == 1) {
    WiFi.softAPdisconnect(true);
    WiFi.mode(WIFI_STA);
  } else {
    WiFi.disconnect();
    delay(30);
  }
  wifi_promiscuous_enable(0);
  wifi_set_promiscuous_rx_cb(onFrame);
  wifi_promiscuous_enable(1);
  for (uint8_t ch = 1; ch <= cfg.maxCh; ch++) {
    wifi_set_channel(ch);
    uint32_t d = (ch == 1 || ch == 6 || ch == 11) ? cfg.dwellMs * 3 / 2 : cfg.dwellMs;  // busiest channels get longer
    uint32_t s = millis();
    while (millis() - s < d) delay(5);
  }
  wifi_promiscuous_enable(0);
  sweepCount++;
  lastSweepMs = millis();
  lastSweepDur = lastSweepMs - t0;
  purge();
  if (cfg.mode == 1) startAP();
  else reconnect();
}

static bool pushData() {
  String u = cfg.push;
  if (!u.startsWith("http://")) return false;
  u.remove(0, 7);
  int slash = u.indexOf('/');
  String hp = slash < 0 ? u : u.substring(0, slash);
  String path = slash < 0 ? String("/") : u.substring(slash);
  int colon = hp.indexOf(':');
  String host = colon < 0 ? hp : hp.substring(0, colon);
  uint16_t port = colon < 0 ? 80 : hp.substring(colon + 1).toInt();
  WiFiClient c;
  c.setTimeout(3000);
  if (!c.connect(host.c_str(), port)) return false;
  c.print(String("POST ") + path + " HTTP/1.1\r\nHost: " + host +
          "\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n");
  ClientSink s(c);
  jsonAll(s);
  s.flushBuf();
  c.print("0\r\n\r\n");
  uint32_t t = millis();
  while (!c.available() && c.connected() && millis() - t < 3000) delay(10);
  String line = c.readStringUntil('\n');
  c.stop();
  return line.indexOf(" 2") > 0;
}

static void sweepCycle() {
  doSweep();
  if (cfg.mode == 0 && cfg.push[0]) {
    if (WiFi.status() == WL_CONNECTED) pushState = pushData() ? 1 : 0;
    else pushState = 0;
  }
  if (cfg.mode == 0 && WiFi.status() == WL_CONNECTED && !timeConfigured && cfg.ntp[0]) {
    configTime(0, 0, cfg.ntp);
    timeConfigured = true;
  }
}

// ───────────────────────── main ─────────────────────────
static uint32_t nextSweep = 0, btnDown = 0;

void setup() {
  Serial.begin(115200);
  Serial.println(F("\n\nESP-01 WiFi Survey " FW_VERSION));
  WiFi.persistent(false);
  pinMode(BTN_PIN, INPUT_PULLUP);
  cfgLoad();
  apName = String("WifiSurvey-") + String(ESP.getChipId(), HEX);
  setupRoutes();
  server.begin();

  if (cfg.mode == 1) {
    startAP();
    Serial.printf("Standalone AP '%s' -> http://192.168.4.1/\n", apName.c_str());
  } else if (cfg.ssid[0]) {
    Serial.printf("Joining '%s'…\n", cfg.ssid);
    if (connectSta(20000)) {
      Serial.printf("Connected, http://%s/  (or http://%s.local/)\n", WiFi.localIP().toString().c_str(), cfg.host);
      MDNS.begin(cfg.host);
      MDNS.addService("http", "tcp", 80);
    } else {
      Serial.println(F("Could not join, starting setup portal"));
      startPortal(true);
    }
  } else {
    startPortal(false);
  }
  nextSweep = millis() + 3000;
}

void loop() {
  server.handleClient();
  if (configMode) {
    dns.processNextRequest();
    if (portalHasCreds && millis() - portalStart > 300000UL) ESP.restart();  // retry saved network
  } else {
    if (cfg.mode == 0) MDNS.update();
    if ((int32_t)(millis() - nextSweep) >= 0) {
      sweepCycle();
      nextSweep = millis() + cfg.intervalS * 1000UL;
    }
  }
  // hold GPIO0 low 5 s -> setup portal
  if (digitalRead(BTN_PIN) == LOW) {
    if (!btnDown) btnDown = millis();
    else if (millis() - btnDown > 5000 && !configMode) startPortal(cfg.ssid[0] != 0);
  } else btnDown = 0;
  delay(1);
}
