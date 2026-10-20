# ESP-01 WiFi Survey

Passive 802.11 survey device for the ESP-01 / ESP-01S (ESP8266). It hops across channels in
promiscuous mode and records every access point and every client device it hears, including
**which AP (BSSID/SSID) each device is talking to**. It never transmits, deauths or injects.

## Build & flash

```
pio run -t upload        # ESP-01 in flash mode: GPIO0 low at power-up
pio device monitor
```

Arduino IDE: copy `src/main.cpp` to `esp01_wifi_survey.ino`, board "Generic ESP8266 Module",
flash size 1 MB, CPU 160 MHz, lwIP "v2 Lower Memory".

## First-time setup (WiFiManager-style)

1. Power it up. With no saved network it opens an AP called `WifiSurvey-xxxxxx`.
2. Join it; the captive portal opens `/config` (or browse to `192.168.4.1`).
3. Tap your network in the scan list, enter the password, adjust options, **Save & reboot**.
4. It joins your network. Open `http://wifisurvey.local/` or its IP (printed on serial at 115200).

Re-enter setup any time: hold **GPIO0 to GND for 5 s** while running, or use `/config`
(password-protected with user `admin` if you set an admin password). If the saved network
can't be joined at boot, the portal opens for 5 minutes, then retries.

Modes: **Join network** (default) or **Standalone AP** (dashboard at `192.168.4.1`, no router needed).

## How the data is collected

The ESP8266 has one radio, so it cannot sniff and stay associated at once. The cycle is:

```
sweep channels 1..N (~4.5 s)  ->  reconnect  ->  serve dashboard / push JSON  ->  idle (default 30 s)
```

- The dashboard/API are unreachable during the sweep + reconnect window (~6-8 s). The dashboard
  retries automatically; pollers should tolerate a failed request.
- Data accumulates across sweeps and is kept in RAM for `keep` seconds (default 900).
  Tables hold 128 devices and 48 APs; when full, the least recently heard entry is replaced.
- Channels 1/6/11 get 1.5x dwell. Raise the per-channel dwell (500-1000 ms) to catch more quiet devices.
- Data is lost on reboot (RAM only). Use the push option or poll regularly to keep history.

## Endpoints

| Path | Description |
|---|---|
| `/` | Live dashboard (filter, click an AP to see its devices) |
| `/api/data` | Everything: `device`, `aps`, `stations` |
| `/api/aps`, `/api/stations` | Arrays only |
| `/api/summary` | Tiny counters (good for Zabbix/Prometheus-style polling) |
| `/export.json` | Same as `/api/data`, as a download |
| `/export.csv` | Devices CSV; `?t=aps` for the AP CSV |
| `POST /api/clear` | Wipe collected data |
| `/config` | Settings |

CORS is open (`*`) on the data endpoints.

**Push:** set "Push JSON after every sweep" to `http://host:port/path`; the device POSTs the full
`/api/data` document (chunked, `application/json`) after each sweep. HTTP only (no TLS on this chip).

### JSON shape

```json
{
  "device": {"id":"WifiSurvey-a1b2c3","fw":"1.0.0","mode":"sta","ip":"192.168.1.50","uptime_s":812,
             "epoch":1760000000,"sweeps":24,"last_sweep_age_s":9,"sweep_ms":4520,
             "ap_count":17,"station_count":41,"associated_count":29,"push":"ok","heap":21480},
  "aps": [{"bssid":"aa:bb:cc:dd:ee:ff","ssid":"Home","hidden":false,"channel":6,"rssi":-58,
           "security":"wpa2/3","clients":4,"frames":912,
           "first_age_s":800,"age_s":3,"first_seen":1759999210,"last_seen":1760000007}],
  "stations": [{"mac":"12:34:56:78:9a:bc","randomized":true,"associated":true,
                "bssid":"aa:bb:cc:dd:ee:ff","ssid":"Home","rssi":-71,"channel":6,"roams":0,
                "probe":null,"frames":57,"first_age_s":500,"age_s":12,
                "first_seen":1759999510,"last_seen":1760000000}]
}
```

`first_seen`/`last_seen` are Unix epochs once NTP has synced (needs internet in "join" mode);
otherwise `null` and you use the `*_age_s` fields.

## Interpreting results

- **associated/bssid**: learned from data frames (station <-> AP), PS-Poll and successful association
  responses. A device that was only heard probing shows `associated:false` and the SSID it is searching for in `probe`.
- **rssi** on a device is only updated from frames *the device itself sent* (an AP's signal
  tells you nothing about the phone). Devices known only from AP-to-client frames have `rssi:null`.
- **roams** counts BSSID changes seen for a device.
- **randomized**: locally-administered MAC bit is set (modern phones rotate MACs per network, so
  one phone can appear as several devices over time).
- **security**: `open` / `secured` (privacy bit seen but encryption IE not captured) / `wpa` / `wpa2/3`.
  The ESP8266 only captures the first 112 bytes of a management frame, so RSN info is sometimes cut off.
- Only traffic present during a channel's dwell time is heard; quiet or sleeping devices may appear
  only after several sweeps. Encrypted payloads are never read, only 802.11 headers.

## Hardware notes

- ESP-01 needs a stable 3.3 V supply (>=300 mA peaks). Poor power is the #1 cause of resets.
- Optional button between GPIO0 and GND for the setup-portal gesture (GPIO0 must be high at power-up
  for normal boot).
- Serial uses the same pins as the blue LED (GPIO1), so there is no spare status LED.

## Settings stored

Saved in emulated EEPROM (one flash sector, no filesystem): network credentials, hostname,
admin password, mode, channel range, dwell/interval/keep times, push URL, NTP server.
