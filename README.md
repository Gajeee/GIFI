# GIFI

A Wi-Fi speed checker that runs in a single HTML file. Measure your download, upload, latency and jitter, see your IP and provider, and check what video quality your connection can handle.

![GIFI home](sc1.jpeg)

![GIFI results](sc2.jpeg)

## Features

- **Speed test**: download, upload, latency and jitter, with a live readout and a test log
- **Connection details**: public IP address, provider (ISP and ASN), location and test server
- **Bitrate**: your speed in Mbps, kbps and MB/s, plus a grade for watching (480p to 4K) and live streaming (480p to 4K)
- **Bitrate checker**: type any bitrate and see if your download and upload can carry it
- **Network Security Audit**: live latency, jitter and loss, plus exposure checks (open from the menu)
- **CPU & GPU stress test**: loads every core and your GPU, then gives CPU, GPU, overall and sustained scores, with system info pulled from your browser (open from the menu)
- **ASCII art hero** with a subtle wave and glitch animation
- No dependencies, no build step, no backend

## Usage

1. Download `index.html`, `network-audit.css`, `network-audit.js`, `stress-test.css` and `stress-test.js` into one folder.
2. Open `index.html` in any modern browser with an internet connection.
3. Press **Start test**, or open the menu for the audit and the stress test.

To host it on GitHub Pages, push all five files to your repo and turn on Pages in the repo settings.

## How it works

| Measurement | Method |
|-------------|--------|
| Latency and jitter | 12 small requests to Cloudflare's speed server. The first is discarded, latency is the median, and jitter is the average difference between samples |
| Download | 4 parallel streams for 8 seconds. The first second is ignored as warm-up |
| Upload | 4 parallel uploads of random data for 7 seconds, with the same warm-up |
| IP and provider | Cloudflare's `/meta` endpoint, with `ipwho.is` as a fallback |

### Stress test

| Measurement | Method |
|-------------|--------|
| System info | Read from the browser: logical cores, rounded memory, platform, display, battery, GPU name, WebGL and WebGPU |
| CPU single-core | 1 Web Worker running an integer and float kernel for 5 seconds. The first second is ignored as warm-up |
| CPU multi-core | One worker per logical core on the same kernel for 10, 20 or 60 seconds |
| GPU | A WebGL fragment shader at a fixed 1280×720, synced every frame, for 10, 20 or 60 seconds |
| Overall | Average of the CPU score (geometric mean of single and multi) and the GPU score |
| Sustained | Last third of the run against the first third. Under 95% means the chip is slowing down under heat |

Scores are GIFI points, a relative scale. Compare them only with other GIFI runs.

Bitrate grades compare your speed to typical bitrates for each quality:

- **Smooth**: your speed is at least 1.5× the bitrate
- **Marginal**: your speed meets the bitrate but with little headroom
- **Too slow**: your speed is below the bitrate

## Notes

- Results show the path between your device and Cloudflare's nearest server, not your provider's advertised speed.
- For the most accurate reading, close other downloads and use one device.
- Location is estimated from your IP and can be off by a city or two. On a VPN, you will see the VPN's details.
- Ad or privacy blockers may block the test requests.
- Browsers hide the CPU model and exact RAM. Cores are logical threads, memory is rounded and capped at 8 GB, and the GPU name can be masked.
- Keep the stress test tab in front. Background tabs are throttled and will score low. Plug in a laptop, and expect fan noise.
- The stress test panel reuses styles from `network-audit.css`, so keep both files together.

## Tech

HTML, CSS and vanilla JavaScript, with Web Workers and WebGL for the stress test. Fonts: Source Serif 4, Inter Tight and JetBrains Mono from Google Fonts.

## Made by

[Gajee Hub](https://gajeee.github.io/Portfolio/) · [GitHub](https://github.com/Gajeee) · [LinkedIn](https://www.linkedin.com/in/gajenes-asitambi-411049347)
