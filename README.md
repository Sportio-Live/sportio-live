

![enter image description here](https://github.com/Sportio-Live/sportio-live/blob/main/public/sportio_logo.png?raw=true)




*Disclaimer: This was created entirely using AI*

Sportio Live is a self-hosted Nuvio/Stremio addon that turns your IPTV into a live sports catalog - today's games, personalized to your timezone, with custom artwork and stream matching. (Xtream and M3U supported, multiple providers per account)

*Sportio Live doesn't provide any streams itself*


[Getting Started](#getting-started) &nbsp;·&nbsp; [Supported Leagues](#supported-leagues) &nbsp;·&nbsp; [Screenshots](#screenshots)

---

## Getting started

**You'll need:** Docker (with Compose), either an Xtream URL + username/password **or** an M3U playlist + EPG URL from your IPTV provider, and a reverse proxy for HTTPS - Stremio and Nuvio both require it to add the addon at all (see [HTTPS](#https) below).

1. Clone the repo and `cd` into it:
   ```bash
   git clone https://github.com/Sportio-Live/sportio-live.git
   cd sportio-live
   ```
2. Create a `.env` file with a login for the admin panel - leave `ENCRYPTION_KEY` out for now, the app generates it for you in step 4:
   ```
   ADMIN_USERNAME=<pick a username for the admin page>
   ADMIN_PASSWORD=<pick a password for the admin page>
   ```
3. Build and start the container:
   ```bash
   docker compose up -d --build
   ```
4. Open `http://<your-server>:2323`. On a fresh install the app walks you through a one-time setup before anything else works:
   - Confirms the admin login (skipped here, since it's already set in `.env`)
   - Generates your encryption key - click **Generate a Key**, paste the value into `.env` as `ENCRYPTION_KEY=<value>`, then restart the container (`docker compose up -d --build`) and click **I've restarted the container - check again**
5. Run the setup wizard: connect your Xtream or M3U provider, then either pick a matching [preset](#presets) or manually choose which IPTV categories to search when browsing games.
6. Copy the manifest link the wizard gives you into Stremio/Nuvio as a custom addon.

> Losing the encryption key means losing every saved Xtream credential permanently - back it up somewhere safe.

### Running a pre-built image (no clone, no build step)

Every update to `main` is published as a ready-to-run image - useful for platforms (Unraid, Synology, Portainer, TrueNAS, Kubernetes, etc.) that expect an image reference instead of building from source.

1. Make a directory for it and `cd` in - `docker compose` will create `data/` and `presets/` here next to the compose file:
   ```bash
   mkdir sportio-live && cd sportio-live
   ```
2. Create a `docker-compose.yml`:
   ```yaml
   services:
     sportio-live:
       image: ghcr.io/sportio-live/sportio-live:latest
       container_name: sportio-live
       restart: unless-stopped
       ports:
         - "2323:2323"
       environment:
         - PORT=2323
         - HOST=0.0.0.0
         - ADMIN_USERNAME=<pick a username for the admin page>
         - ADMIN_PASSWORD=<pick a password for the admin page>
       volumes:
         - ./data:/usr/src/app/data
         - ./presets:/usr/src/app/presets
   ```
3. Pull and start it:
   ```bash
   docker compose up -d
   ```
4. Open `http://<your-server>:2323`. On a fresh install the app walks you through a one-time setup before anything else works:
   - Confirms the admin login (skipped here, since it's already set above)
   - Generates your encryption key - click **Generate a Key**, add the value to the `environment:` block above as `ENCRYPTION_KEY=<value>`, then restart the container (`docker compose up -d`) and click **I've restarted the container - check again**
5. Run the setup wizard: connect your Xtream or M3U provider, then either pick a matching [preset](#presets) or manually choose which IPTV categories to search when browsing games.
6. Copy the manifest link the wizard gives you into Stremio/Nuvio as a custom addon.

To update, `docker compose pull && docker compose up -d`.

### Updating

```
git pull
docker compose up -d --build
```

### HTTPS

Sportio Live doesn't handle TLS itself, and this isn't just a hardening tip - Stremio and Nuvio both refuse to add an addon that isn't served over HTTPS, so plain HTTP only gets you as far as local testing. Put a reverse proxy in front (Nginx Proxy Manager, Caddy, Traefik) with a real certificate; it also protects the IPTV credentials passing through the wizard and dashboard. If your proxy shares a Docker network with other containers, make sure Sportio Live joins that same network in `docker-compose.yml`.

---

## Multi-provider support

One account can connect more than one Xtream or M3U provider - each gets its own tab in the dashboard with its own credentials, categories, and EPG source picks. When a game airs, channels from every connected provider are searched together, and a match's provider is labeled whenever an account has more than one.

## Presets

The wizard offers a preset step between connecting a provider and finishing setup - picking one fills in leagues, categories, and EPG overrides in one click instead of configuring from scratch. Presets come from two places: stock presets ship with the app and update via `git pull`, while admins can import any user exported configuration file from the admin panel and publish it as a local preset for their own instance. Presets added or changed by an update sit pending until reviewed.

## Stream matching

A channel that clears any tier gets shown, ordered by how confident the match actually is - and a channel that also mentions an unrelated team gets excluded outright. Deduplication is done at the end to remove duplicate URLs shared across channel categories/folders.

| Tier | Requires|
|--|-
|1| "4K" appears somewhere, and both team names are confirmed (name and/or description)
|2| Both team names appear in the channel name **and** both also appear in the description
|3| Both team names appear somewhere across name + description combined, not necessarily in the same field
|4| Just one team's actual nickname (e.g. "Knicks," not "New York") appears in the channel name — a city/state-only match doesn't count

## Formatter

Custom formatting for Name and Description fields. 

## EPG

Sportio Live can layer in guide data from [epgshare01.online](https://epgshare01.online/epgshare01/) alongside whatever your provider already sends, letting a channel's EPG source be overridden per channel or per provider. Which EPGShare01 feeds get fetched and cached is controlled per-instance from the admin panel - see [Admin panel](#admin-panel) below.

## Matchup art

Posters and backgrounds all display custom matchup art for each game.


## Upcoming Schedules
Each league includes a dummy "game" to display the next 20 upcoming games for that league.


## Timezone-aware

Every account has its own configured timezone with the actual date and time baked into each poster, upcoming league schedule, and game descriptions. Timezones can be changed after the fact in the configuration page.



## Supported leagues

| Sport | Leagues |
|---|---|
| Baseball | MLB |
| Basketball | NBA, WNBA, NCAA Men's, NCAA Women's |
| Football | NFL, NCAA Football |
| Hockey | NHL |
| Soccer | Premier League, MLS, La Liga, FIFA World Cup |
| Cricket | IPL |
| Combat | UFC |
| Aussie Rules | AFL |
| Rugby | United Rugby Championship, Premiership Rugby |

---

## Admin panel

Setting `ADMIN_USERNAME`/`ADMIN_PASSWORD` unlocks `/admin.html`, a separate login-gated panel for running the instance day to day:

- **Refresh schedule** - set days/times to automatically refresh cached M3U and EPG data, or trigger a refresh on demand.
- **EPG Editor** - pick which EPGShare01 feeds this instance keeps fetched and cached, so users can select them as a per-channel EPG override.
- **Presets** - import a user configuration file as an instance preset. Review/publish anything an update adds or changes before it reaches users.
- **Accounts** - browse registered accounts, filterable by created or last-accessed date.

## Project structure

```
server.js                     Express app - manifest, catalog, stream matching, art generation
public/index.html             Setup wizard + configuration dashboard
public/admin.html             Admin panel - EPG, presets, accounts
assets/posters/                 Poster overlay art
assets/background/              Landscape background overlay art
assets/background/schedule/     "Upcoming Schedule" placeholder art, one photo per sport
presets/presets.json            Stock presets shipped with the app (git-tracked)
data/local-presets.json         Presets created via this instance's admin panel (auto-created, gitignored)
data/users.json                 Registered accounts (auto-created, gitignored)
```

---

## Security

Xtream/M3U credentials are encrypted at rest (AES-256-GCM).

## Disclaimer

Sportio Live requires an existing, legitimate IPTV subscription. It does not provide, host, or distribute any streams or content of its own.

---
## Screenshots

### Addon:
![enter image description here](https://github.com/Sportio-Live/sportio-live/blob/main/screenshots/addon/1.jpegli.jpg?raw=true)
![enter image description here](https://github.com/Sportio-Live/sportio-live/blob/main/screenshots/addon/2.jpegli.jpg?raw=true)
![enter image description here](https://github.com/Sportio-Live/sportio-live/blob/main/screenshots/addon/3.jpegli.jpg?raw=true)
![enter image description here](https://github.com/Sportio-Live/sportio-live/blob/main/screenshots/addon/4.jpegli.jpg?raw=true)
![enter image description here](https://github.com/Sportio-Live/sportio-live/blob/main/screenshots/addon/5.jpegli.jpg?raw=true)
![enter image description here](https://github.com/Sportio-Live/sportio-live/blob/main/screenshots/addon/6.jpegli.jpg?raw=true)

###  Setup:
![enter image description here](https://github.com/Sportio-Live/sportio-live/blob/main/screenshots/setup/1.png?raw=true)
![enter image description here](https://github.com/Sportio-Live/sportio-live/blob/main/screenshots/setup/2.png?raw=true)
![enter image description here](https://github.com/Sportio-Live/sportio-live/blob/main/screenshots/setup/3.png?raw=true)
![enter image description here](https://github.com/Sportio-Live/sportio-live/blob/main/screenshots/setup/4.png?raw=true)
![enter image description here](https://github.com/Sportio-Live/sportio-live/blob/main/screenshots/setup/5.png?raw=true)
![enter image description here](https://github.com/Sportio-Live/sportio-live/blob/main/screenshots/setup/6.png?raw=true)
![enter image description here](https://github.com/Sportio-Live/sportio-live/blob/main/screenshots/setup/7.png?raw=true)
![enter image description here](https://github.com/Sportio-Live/sportio-live/blob/main/screenshots/setup/8.png?raw=true)

### Admin Panel:
![enter image description here](https://github.com/Sportio-Live/sportio-live/blob/main/screenshots/admin/1.png?raw=true)
![enter image description here](https://github.com/Sportio-Live/sportio-live/blob/main/screenshots/admin/2.png?raw=true)
![enter image description here](https://github.com/Sportio-Live/sportio-live/blob/main/screenshots/admin/3.png?raw=true)
![enter image description here](https://github.com/Sportio-Live/sportio-live/blob/main/screenshots/admin/4.png?raw=true)

