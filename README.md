# Sniff Probes

Plug-and-play Perl script for sniffing 802.11 probes requests. 

## What are Probe Requests?

Probe requests are an 802.11 WIFI packet type that function to automatically connect network devices to the wireless access points (APs) that they have previously associated with. Whenever a phone, computer, or other networked device has Wi-Fi enabled, but is not connected to a network, it is constantly "probing"; openly broadcating the network names (SSIDs) of previously connected APs. Because wireless access points have unique and often personal network names, it is easy to identify the device owner by recognizing the names of networks they frequently connect to.

## Sniffing Probe Requests

```Perl
# Type "ifconfig" to list available network devices.
# Wireless devices generally start with a "w"
IFACE=wlan0 perl ./probe-sniffer.pl
```

Requires **tcpdump** and **Perl** (v5.38+). Both of these packages are installed on many *nix* systems by default, but if they aren't you will have to install them manually. Your wireless device must also support monitor mode. Here is [a list of WiFi cards that support monitor mode](https://www.wirelesshack.org/best-kali-linux-compatible-usb-adapter-dongles-2016.html) (2018).

Prints `timetamp`, `signal strength`, `sender MAC address` and `SSID` to screen. Saves output as a space-delimeted "csv" to `probes.txt` by default.

Additional options:

```console
IFACE=wlan0 OUTPUT=output.txt CHANNEL_HOP=1 perl ./probe-sniffer.pl
```

`CHANNEL_HOP=1` enables channel hoping on `IFACE` every two seconds. This is used to increase the number of probes captured. Disabled by default.
