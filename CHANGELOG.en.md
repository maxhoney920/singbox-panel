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
