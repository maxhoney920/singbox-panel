## 2.7.1
- Test update with no changes: checking the panel update mechanism.

## 2.7.0
- The panel checks for updates when you open the web interface (at most once every 10 minutes; nothing is installed without your consent).
- A "Updates available" message with a "Go to installation" button is shown above the connection status; it can be closed with the cross and returns only when a new version appears.
- Built-in preset lists are synchronised with the repository (version 8, the "Kimi (Moonshot AI)" preset).

## 2.6.2
- Minor interface improvements.

## 2.6.1
- The top menu (Status, Servers, …) is now exactly centred in the window on wide screens (1200 px and up); logo on the left, language/theme/log out on the right. Narrow and mobile layouts are unchanged.
- Clicking the logo and the "sing-box Panel" title opens the Status tab (keyboard works too).

## 2.6.0
- Servers tab: the selection dots are gone. The current server is already marked by the highlighted row with an accent bar on the left and a bold name.
- Settings → Server: new "Auto-restart on low RAM" card. The panel detects the device's RAM size and shows how much is used. When enabled (OFF by default), if usage stays at or above the threshold (85 % by default, 50–95 % allowed) for three samples in a row (≈1 minute) and sing-box holds at least 10 % of RAM, the panel restarts sing-box. At most once per 10 minutes; if the memory is used by something else, no restart happens and the card says so. The time and load of the last auto-restart are saved.
- Xray for XHTTP: added a warning that Xray is a separate process that needs additional RAM (≈30 MB idle as measured on x86_64; more under load and possibly on ARM). The warning is shown in the card and in the enable confirmation, together with the device's available RAM.

## 2.5.12
- "Chocolate4U ru-direct": the `geosite-ru` and `geoip-ru` lists are now removed individually. Previously, if at least one of them was used by another rule (for example a DNS rule with `rule_set: geosite-ru`), both stayed and the card hung in "partially configured" forever. Now only the one that is really needed stays, and an orphaned one (declared but unused — sing-box still downloads it on every start) is removed by the "Remove leftovers" button. The card says which lists are unused
- A list needed only by someone else's rule or by DNS is no longer treated as a leftover and no longer gets in the way

## 2.5.11
- "Chocolate4U ru-direct": if the rule was removed by hand but the `geosite-ru`/`geoip-ru` lists remain ("partially configured" state), the card now has a "Remove leftovers" button and a note that sing-box downloads declared lists on every start even when no rule uses them (without the cache, with GitHub unreachable the service will not start). Previously this state offered only "Complete and enable"
- Fixed: on disable, a rule that was already put back by hand is not duplicated

## 2.5.10
- The Russian lists are now a separate optional set "Chocolate4U ru-direct" (Routing tab). Until you enable it, the config and your existing rules work as before. When enabled, the set removes the other "Russian" rules that go direct and are fully covered by these lists: the "Russian domains (.ru, .su, .рф)" preset, old geoip/geosite rules for ru and separate rules that use only the geosite-ru/geoip-ru tags. Rules with other conditions (for example `ru` together with another domain, a port, a different outbound) and DNS rules are not touched. The confirmation window shows the exact list of rules to be removed before enabling
- On disable the removed rules return to their places, and the geosite-ru/geoip-ru lists are dropped only if no rule uses them any more (otherwise they stay). If new redundant Russian rules appear, an enabled set offers a "Remove redundant rules" button. Fixed: restored rules that refer to the list tags no longer leave the config with undefined tags

## 2.5.9
- New button "Russian lists direct (geosite-ru, geoip-ru)" on the "Routing" tab (nothing is added by default). It adds two ready-made rule_sets (Russian domains and Russian IP addresses) to the config and a "they → direct" rule at the end of the rule list: presets and your own rules above it take priority. sing-box downloads the lists itself from GitHub (Chocolate4U/Iran-sing-box-rules) through the "proxy" server and refreshes them daily; on sing-box 1.14 and newer `http_client` is used instead of the deprecated `download_detour`
- The button always enables the sing-box cache (`cache_file`): without it sing-box fails to start on every restart if the lists could not be downloaded. After applying, the panel separately checks that sing-box got through the list download; if not, the previous config is restored. If such lists are already in the config, the button recognises them and duplicates nothing. "Disable" removes the lists and the rule but leaves the cache alone, and refuses if the tags are used by other rules or DNS

## 2.5.8
- The settings "Direct mode when stopped", "Xray for XHTTP" and "Services on this device through the proxy" moved from "Settings → Updates" to "Settings → Network": they concern network behaviour, not updates. The settings themselves work as before

## 2.5.7
- Fixed: when a phone or PC uses "this device's address:1081" as its proxy, requests to services on the device itself that are published through Docker (for example Lampa on port 9118) returned 502. Cause: sing-box's direct outbound is bound to the network card, and Docker ports do not respond through such binding. The new optional setting "Services on this device through the proxy" (Settings → Updates; off by default) adds a separate direct outbound bound to loopback and a rule: requests to the device's own addresses go to 127.0.0.1. Other traffic is unchanged. Requires sing-box 1.11 or newer

## 2.5.6
- New optional setting "Direct mode when stopped" (Settings → Updates; off by default). If devices on the network use "this device's address:1080/1081" as their proxy, they used to lose internet when sing-box was stopped. Now, while sing-box is stopped, the panel holds the same ports (SOCKS5 and HTTP) and passes traffic directly; when sing-box starts, the ports go straight back to it. Local-network addresses only, UDP over SOCKS is not supported

## 2.5.5
- Fixed: Lampa and other Docker containers stopped opening while TUN was on. The TUN address 172.19.0.1/30 coincided with a Docker network address (172.19.0.1/16), and replies between docker-proxy and the container went into the tunnel
- The panel now detects when the TUN address overlaps with the device's networks (Docker bridges, WireGuard, etc.), shows a warning in "Status" and offers a "Change the address to …" button. Nothing is changed automatically
- A new TUN created from the panel gets a free subnet (198.18.0.1/30 or another), not the fixed 172.19.0.1/30

## 2.5.4
- New optional set "Google by IP addresses (push services, apps)": Google ranges (74.125.0.0/16, 142.250.0.0/15, etc.) so that mobile apps and the push channel (port 5228), which connect by IP, take the same server as Gemini. Nothing is added by default

## 2.5.3
- The "Gemini" set now includes Google sign-in and UI domains (accounts.google.com, ogs.google.com, play.google.com, www.google.com, apis.google.com, ssl.gstatic.com, csp.withgoogle.com, etc.) and sign-in service APIs (oauth2, oauthaccountmanager, accountcapabilities-pa, growth-pa, notifications-pa, signaler-pa, robinfrontend-pa on googleapis.com): according to the sing-box log they took the default route through a different server, and Google, seeing sign-in and Gemini from different addresses, reported an unavailable region
- New optional set "All of Google (sign-in, search, services)": sends google.com, googleapis.com, gstatic.com and related domains to the same server as Gemini — if you need all of Google to take one path. Nothing is added by default

## 2.5.2
- The "Gemini / AI Studio / NotebookLM" set now includes the domains without which Gemini reports an unavailable region when a specific server is chosen: Google sign-in and page resources (www.gstatic.com, fonts.gstatic.com, googleusercontent.com, fonts.googleapis.com, recaptcha.net, analytics.google.com, google.ru, clients6.google.com, voice input). Before, only Gemini's own domains went to the chosen server, while the rest took the default route from a different IP. All of google.com is NOT sent through the server. "ChatGPT / OpenAI / Claude" gained intercomcdn.com and intercom.io (support chat)
- "Preset sets" and "BitTorrent direct" in the interface no longer insert rules above the "Xray direct" rule

## 2.5.1
- Xray for XHTTP: the "Xray direct" rule now sits above the DNS hijack (hijack-dns), so Xray's own DNS queries do not go through sing-box and its proxy (otherwise, with a domain as the server address, a loop is possible: finding the XHTTP server requires the server itself). New route sets and the local network rule are no longer inserted above it. The rule is moved at the next subscription update

## 2.5.0
- XHTTP nodes through Xray (optional): sing-box does not support the XHTTP transport, so such nodes from subscriptions did not work before. "Settings → Updates → Xray for XHTTP": the "Install and enable" button downloads Xray from GitHub (with a checksum check), reloads the subscriptions and creates a separate `singbox-panel-xray` service. In sing-box such a node looks like a regular one (with the same name), so server selection, the backup server, routes, TUN and the gateway work as before. XHTTP parameters (path, host, mode, extra, tls/reality) are taken from the link. Xray's own traffic bypasses the tunnel (the "process xray → direct" rule) so there is no loop
- Xray can be updated (with a rollback if the new version does not start), disabled (XHTTP nodes are removed from sing-box) and removed; "Delete everything" removes it too. While Xray is off, XHTTP nodes are skipped with a clear reason instead of being added in a broken state

## 2.4.1
- Preset routing sets are no longer placed above the "local network direct" rule: the local addresses rule always stays first (after sniff and hijack-dns), so domain sets (Gemini, OpenAI, Avito, etc.) do not intercept traffic to the local network. If the order is already broken, add the "Local addresses" set (direction "direct") once more — the rule moves back to its place
- The OpenAI / Claude sets were extended, and Gemini / AI Studio / NotebookLM and Avito sets were added

## 2.4.0
- New look in the SafeBridge style: dark blue tones and an orange accent, a logo in the header and on the browser tab, the menu and sub-tabs are segmented switches
- Light theme and a theme button in the header: auto (as in the system), dark, light — the choice is remembered in the browser
- Home page: a large "Connected / Disconnected" panel with the server, uptime and a switch that starts or stops sing-box
- "Servers": the selected server is highlighted, the delay is shown in green, the rows are larger

## 2.3.1
- Phone layout: a compact header (the menu scrolls in one line, language and "Log out" on top), settings sub-tabs in one line, backup and routing rule tables turn into cards, long names and JSON wrap, nothing goes beyond the screen edge
- Fixed the date of sing-box binary backups: "1970-01-01" was shown for a binary from a package

## 2.3.0
- sing-box update: if the new version does not accept the config because of outdated fields, the panel converts them to the new format (DNS servers address → type, dns rules with outbound → domain_resolver, tun inet4_* fields, sniff/domain_strategy on inbounds, block/dns outbounds → reject/hijack-dns actions), checks the result with the new version and shows the list of changes. The config is written only during installation, the previous one is kept; if the service does not come up, both the binary and the config are restored
- sing-box messages are shown without color codes like "[31mFATAL[0m"
- "Settings → Config → Compatibility": a "Convert outdated fields to the new format" button for the installed version (with a preview of the changes)

## 2.2.2
- Update counters on menu items: "Settings" and "Updates" show how many updates are available (panel, sing-box, system packages; red if there is a panel or security update), "Routing" shows how many rules come from outdated preset lists. Details are in the tooltip. No other notifications

## 2.2.1
- sing-box update: the "Install" button is active right away — it downloads and checks the selected version by itself (before, it stayed disabled until "Download and check" was pressed)
- sing-box from an apt package: the package can be pinned (apt-mark hold) — with a checkbox during installation or the "Pin now" button, so apt upgrade does not bring back the repository version; the pin is removed with a button

## 2.2.0
- Operating system updates from the panel ("Settings → Updates → Operating system", Debian/Ubuntu): checking for available updates (apt-get update) with a package list and security updates marked, updating (upgrade or full-upgrade) as a separate background job with progress and a log, and a reboot button when the system asks for it. Everything only on buttons
- The "sing-box update" tab is renamed to "Updates": it holds the panel, sing-box and the system

## 2.1.5
- The changelog is now available in English too: in the panel's "What's new" (in the English interface) and in GitHub release notes

## 2.1.4
- Login: the "Wrong login or password" error is shown in a clear red box, the form shakes and the fields are highlighted in red; while the password is being checked the button shows "Checking…"
- New language switcher: a button with a globe and the current language (RU/EN); clicking it opens a "Язык / Language" menu with Auto, Русский, English and a check mark on the selected one

## 2.1.3
- "What's new" is now about the panel itself: the "Web panel update" card has a collapsible list of changes for the available version (expanded right away) and for the installed version together with earlier ones. The installed version's changes are visible even without checking for updates
- Collapsible lists look neater: frame, arrow indicator, version tags
- Removed the "What's new" block from the sing-box update section

## 2.1.2
- "Check for preset updates" on the "Routing" tab is now a regular button instead of a link
- New preset set: Reddit (preset lists version 2 — 2.1.x panels get it from GitHub without updating)
- "sing-box update": "What's new" under the selected version (release notes from GitHub, expanded for a newer version) and links to the release and the full changelog
- New panel versions and preset lists are checked every 2 hours instead of once a day (installation is still only on a button)
- The language switcher is more compact, the header fits on one line again

## 2.1.1
- Instead of the EN/RU button — a "🌐 Язык / Language" choice: Auto (by browser or system language), Русский, English. The list shows the current choice, and "Auto" shows which language was detected

## 2.1.0
- Preset routing sets are updated separately from the panel: the lists are stored in the GitHub repository (presets.json), the panel downloads fresh ones once a day (and via the "check for preset updates" link on the "Routing" tab). New lists reach the config only with the "Update set lists" button
- New sets from the repository appear in the "Preset sets" list right away

## 2.0.1
- Panel updates now come from GitHub releases (maxhoney920/singbox-panel), and the Google Drive folder stays as a backup source: if GitHub is unavailable, checking and downloading go there. The package is downloaded from the same source as latest.json; the update card shows where the version came from

## 2.0.0
- English interface: an EN/RU button in the header and on the login page (the language is remembered, the browser language is the default)
- First sing-box installation: the config and service left over from a previous sing-box are renamed (not deleted) and new ones are created — with an explanation in the message
- Progress bar when downloading and installing sing-box, when updating the panel and in the quick start wizard; the console installer shows its steps
- The home page shows the subscription expiry date and remaining traffic (if the subscription server reports them)
- Keys without a subscription: "+ Add key (vless://…)" — vless, vmess, trojan, ss, hysteria2
- All-time traffic, not only the current sing-box session (with a "reset" button)
- Chart scale: window from 1 minute to an hour, mouse wheel, logarithmic scale, tooltip with the value under the cursor
- Tab icon (favicon)

## 1.9.1
- A sing-box service you stopped no longer starts by itself: subscription auto-update and preset updates at panel startup only save the config in that case, without restarting the service

## 1.9.0
- Backup server ("Servers" → "Backup server"): the panel checks the primary server and on failure switches the group to the backup, then back when the primary works again. Enabled only by a button

## 1.8.7
- The "local network direct" rule added by the TUN button no longer goes before sniff: domain rules (YouTube etc.) must come after sniff, otherwise they do not match TUN traffic

## 1.8.6
- First sing-box installation: fixed the "initialize cache-file: open cache.db: permission denied" error when /var/lib/sing-box was left from a previous installation under another user

## 1.8.5
- Login via its own PAM service /etc/pam.d/singbox-panel: on Debian 10 root could not log in because of pam_securetty ("cannot determine user's tty")

## 1.8.4
- The panel works on Python 3.7 (Debian 10 "buster"): the python3 requirement was lowered from 3.8 to 3.7

## 1.8.3
- Fixed: after a panel update, "version available" could stay lit for up to a day (a saved answer from the old version was used). Now "is it newer" is recalculated immediately

## 1.8.2
- Updating the panel with the button now also works for a panel installed by the installer or install.sh: the deb package is installed on top, keeping settings and data

## 1.8.1
- Fixed: when installed via singbox-panel-installer.sh, "version available" was always lit at the bottom (the version was not stamped). A version without a number no longer offers updates

## 1.8.0
- "Quick start": Esc and "Close" only close the window for now, the "Don't show again, I'll set it up myself" button removes it for good
- "Settings → Server → Delete everything": restores everything (gateway, service, config, subscriptions, backups, panel settings); confirmed by typing the word DELETE. The sing-box binary and service are removed only if the panel installed them
- The gateway description explains that for sing-box on this device only, the gateway does not need to be enabled

## 1.7.0
- Quick start wizard: at the first login, if sing-box is not installed, it offers to install it, add a subscription, enable TUN, route Russian domains and BitTorrent directly. Shown once, can be skipped and everything configured manually

## 1.6.0
- "Help" tab: quick start, description of sections, common problems and console commands, with search

## 1.5.8
- The "safe-internet" signature became a link to the Telegram bot

## 1.5.7
- When checking for updates, the changes of all versions newer than the installed one are listed

## 1.5.6
- Service version for testing auto-update

## 1.5.5
- Update source: a shared Google Drive folder

## 1.5.4
- "Made with love by safe-internet" signature on the login page and at the bottom of the panel

## 1.5.3
- Update: new version check once a day, installation only on a button
- The update source address is built into the package

## 1.5.2
- Updating the panel itself from your own file server: sha256 check, installation via dpkg, rollback to three versions

## 1.5.1
- "DNS in sing-box": DNS query interception and listening on :53 so that gateway clients can resolve names

## 1.5.0
- Docker and the 3proxy container were removed from the panel; the built-in SOCKS5/HTTP proxy in sing-box remains

## 1.4.1
- The traffic chart on the home page counts all sing-box traffic (Clash API), not only the TUN interface

## 1.4.0
- SOCKS5 and HTTP proxy directly in sing-box: faster and without the extra path through Docker and TUN

## 1.3.7
- Fixed: the BitTorrent rule could be overwritten by the "Save and apply" button

## 1.3.5
- Adding a route set again does not create duplicates but changes the direction

## 1.3.3
- Preset route sets are updated together with the panel; the rules table shows which set a rule belongs to

## 1.3.2
- "BitTorrent (P2P) always direct" switch

## 1.3.1
- "Enable TUN" button if the config has no TUN

## 1.3.0
- Preset routing sets (YouTube, Telegram etc.), a hint on the "Servers" tab, server choice on the home page

## 1.2.8
- "Route all traffic here" button on a server group

## 1.2.7
- The base config at first installation includes the Clash API; a new subscription group becomes the default route

## 1.2.6
- First sing-box installation right from the panel (binary, service and a minimal config)
