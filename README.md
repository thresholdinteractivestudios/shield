# Shield — Social Engineering Protection
**by Threshold Interactive Studios**

> Stop scams before you fall for them.

Shield monitors your clipboard in real time and alerts you the moment you copy suspicious content — from any app, any platform, before you can act on it.

---

## What it does

When you copy text from **any** messaging app, email client, or website, Shield scans it instantly against 300+ scam patterns across 12 categories. If something looks like a social engineering attempt, an alert fires in the corner of your screen within one second — before you paste, click, or reply.

**It catches:**
- Authority impersonation (IRS, Microsoft, Apple, your bank)
- Phishing links and spoofed domains
- Fake urgency and deadline pressure
- Credential and payment requests
- Romance scams and pig butchering
- Grandparent scams
- Fake job offers
- Crypto recovery fraud
- And more

## Privacy — your data never leaves your machine

Shield has **no servers, no accounts, no telemetry**. Everything runs locally. The detection engine is a single JavaScript file on your hard drive. Zero network requests are made during scanning.

- No account required
- No clipboard content stored beyond your session
- No data transmitted anywhere
- Works completely offline
- Fully open source

## Installation

### Option A — Download installer (recommended)
Download `Shield Setup 1.0.0.exe` from the [Releases](https://github.com/ThresholdInteractiveStudios/shield/releases) page. Run it. Done.

### Option B — Run from source
```bash
git clone https://github.com/ThresholdInteractiveStudios/shield.git
cd shield
npm install
npm start
```

**Requirements:** Windows 10/11 64-bit, Node.js 18+

## Building the installer
```bash
npm run build
# Output: dist/Shield Setup 1.0.0.exe
```

## How it works

Shield uses a rule-based detection engine with no AI or cloud dependency. Every pattern is explicit, auditable, and documented in `engine.js`.

Detection categories and their weights:

| Category | Weight | Examples |
|---|---|---|
| Payment request | 45 | Gift cards, wire transfer, crypto, Zelle |
| Threat | 40 | Arrest, warrant, suspended, compromised |
| Credential | 40 | Verify identity, SSN, remote access |
| Grandparent scam | 40 | "It's me grandma", bail money |
| Crypto recovery | 45 | "Recover lost crypto", blockchain expert |
| Authority | 35 | IRS, Microsoft, Apple, your bank |
| Phishing | 35 | Suspicious domains, IP links, URL shorteners |
| Job scam | 35 | Work from home, reshipping, mystery shopper |
| Isolation | 30 | "Don't tell anyone", "keep this secret" |
| Romance/pig | 30 | Trading platform, investment returns |
| Urgency | 25 | Act now, 24 hours, final notice |
| Reward | 20 | You won, unclaimed funds, lottery |

Multiple categories firing together increases the score multiplicatively.

**Risk levels:**
- `CRITICAL` (120+) — Very likely a scam
- `HIGH` (70–119) — Strong indicators
- `MEDIUM` (35–69) — Suspicious patterns
- `LOW` (15–34) — Worth reviewing

## Project structure
```
shield/
├── main.js          # Electron main — tray, windows, clipboard monitor
├── engine.js        # Detection engine — all rules and scoring
├── preload.js       # Secure IPC bridge
├── package.json
├── landing/         # Product landing page
│   └── index.html
└── src/
    ├── index.html   # Main app window
    └── alert.html   # Alert popup
```

## Contributing

Pull requests welcome. If you know of scam patterns we're missing — especially regional or less-documented ones — open an issue or submit a PR to `engine.js`.

## License

MIT — free for personal and commercial use.

## Legal

Shield is provided as-is without warranty. Threshold Interactive Studios is not responsible for any scams that are not detected. The detection engine catches common patterns but is not infallible. Always use judgment.

---

**Threshold Interactive Studios** — Building free tools for everyone.  
Also check out **[BootKit Pro](https://github.com/ThresholdInteractiveStudios/bootkitpro)** — professional security toolkit for system repair, pentesting, and forensics.
