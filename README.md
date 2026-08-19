

![enter image description here](https://github.com/Sportio-Live/sportio-live/blob/main/public/sportio_logo.png?raw=true)




*Disclaimer: This was created entirely using AI*

Sportio Live is a self-hosted Nuvio/Stremio addon that turns your IPTV into a live sports catalog - today's games, personalized to your timezone, with custom artwork and stream matching. (Xtream and M3U supported)

*Sportio Live doesn't provide any streams itself* - it bridges ESPN's schedule data with the live channels of your own IPTV.


[Supported Leagues](#supported-leagues)


[Screenshots](#screenshots)


## Setup

A guided wizard gets a new account running in a few clicks - pick your leagues, set your timezone, enter your Xtream or M3U credentials, then choose which IPTV categories/folders should be searched per league. Done.

## Stream matching

A channel that clears any tier gets shown, ordered by how confident the match actually is - and a channel that also mentions an unrelated team gets excluded outright. Deduplication is done at the end to remove duplicate URLs shared across channel categories/folders.

| Tier | Requires|
|--|-
|1| "4K" appears somewhere, and both team names are confirmed (name and/or description)
|2| Both team names appear in the channel name **and** both also appear in the description
|3| Both team names appear somewhere across name + description combined, not necessarily in the same field
|4| Just one team's actual nickname (e.g. "Knicks," not "New York") appears in the channel name — a city/state-only match doesn't count

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
| Combat | UFC |

---

## Getting started


**Requirements:** Docker, Xtream URL & username/password ***or*** M3U playlist & EPG URL,  a reverse proxy for HTTPS (recommended).

1. Clone the repo and `cd` into it.
2. Generate an encryption key.
3. Create a `.env` file:
   ```
   ENCRYPTION_KEY=<paste the key you generated>
   ADMIN_USERNAME=<pick a username for the admin page - optional>
   ADMIN_PASSWORD=<pick a password for the admin page - optional>
   ```
4. Build and start: `docker compose up -d --build`
5. Open `http://<your-server>:2323` and run the setup wizard.
6. Copy your manifest link into Stremio/Nuvio as a custom addon.

> Losing the encryption key means losing every saved Xtream credential permanently - back it up somewhere safe.

### HTTPS

Sportio Live doesn't handle TLS itself. Running it behind a reverse proxy (Nginx Proxy Manager, Caddy, Traefik) with a real certificate is strongly recommended, since IPTV credentials pass through the wizard and dashboard. If your proxy shares a Docker network with other containers, make sure Sportio Live joins that same network in `docker-compose.yml`.

---

## Project structure

```
server.js                     Express app - manifest, catalog, stream matching, art generation
public/index.html             Setup wizard + configuration dashboard
assets/posters/               Poster overlay art
assets/background/            Landscape background overlay art
assets/background/schedule/   "Upcoming Schedule" placeholder art, one photo per sport
data/users.json               Registered accounts (auto-created, gitignored)
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

