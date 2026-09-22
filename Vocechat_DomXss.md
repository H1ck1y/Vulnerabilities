# DOM-based Cross-Site Scripting (XSS) in VoceChat `widget.html` via `welcome` Parameter

## Summary

VoceChat (Privoce) is vulnerable to DOM-based Cross-Site Scripting (XSS). The `welcome` query parameter on `widget.html` is read from the URL and inserted into the DOM without sanitization or encoding, allowing an attacker to execute arbitrary JavaScript in the context of the VoceChat origin via a crafted link. In testing, this was used to exfiltrate the victim's `localStorage`, which contains the live `VOCECHAT_TOKEN` (session/auth token) and `VOCECHAT_CURR_UID`, allowing full session hijacking.


## Vulnerability Classification

- **CWE-79** — Improper Neutralization of Input During Web Page Generation ('Cross-Site Scripting')
- Sub-type: **DOM-based XSS** (reflected via URL parameter, no server round-trip required)

## Environment Setup

```bash
docker run -d --restart=always \
  -p 3001:3000 \
  --name vocechat-server \
  privoce/vocechat-server:latest
```

As deployed in testing: container `vocechat-server`, image `privoce/vocechat-server:latest`, port mapping `0.0.0.0:3001->3000/tcp`.

## Steps to Reproduce

1. Start VoceChat as shown above and confirm it is reachable at `http://localhost:3001`.
2. Log in as a victim user so a session token is present in `localStorage`.
3. Visit the following URL:

   ```
   http://localhost:3001/widget.html?welcome=%3Cimg%20src%3Dx%20onerror%3D%22alert(JSON.stringify(localStorage))%22%3E
   ```

4. A JavaScript `alert()` fires immediately, dumping the full contents of `localStorage` — including `VOCECHAT_TOKEN` and `VOCECHAT_CURR_UID` — confirming arbitrary script execution in the victim's authenticated session.

## Proof of Concept

**Payload URL:**
```
http://localhost:3001/widget.html?welcome=<img src=x onerror="alert(JSON.stringify(localStorage))">
```

**Result (redacted):**

![PoC: alert() dumping localStorage including VOCECHAT_TOKEN](images/20260922211115_92_163.png)


> The captured value is a complete, valid session JWT (`VOCECHAT_TOKEN`) plus the associated user ID. An attacker in possession of this token can impersonate the victim without needing their password, i.e. full account/session takeover — not just data disclosure.

## Root Cause

The `welcome` value is read client-side from the URL (e.g. via `location.search`) and written into a dangerous DOM sink (most likely `innerHTML` or equivalent) without sanitization or output encoding, so any HTML/JS supplied in the parameter executes in the page's origin.

## Impact

- Theft of the session token (`VOCECHAT_TOKEN`) → full account takeover / session hijacking, confirmed in PoC
- Exfiltration of any other sensitive data stored in `localStorage`/`sessionStorage`
- Actions performed on the victim's behalf (message sending, account changes, etc.)
- Phishing, redirection, or defacement of the widget page
- Attack requires only that the victim click a crafted link while logged in — no other interaction needed

## CVSS v3.1

Because the PoC demonstrates actual theft of a valid session token (not just a benign alert), confidentiality and integrity impact should be scored **High**, not Low:

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N
```

**Score: 8.7 (High)**

## Remediation

- Never write user-controlled input into `innerHTML` / `document.write`; use `textContent` or safe DOM APIs instead.
- If HTML rendering of this parameter is genuinely required, sanitize with a vetted library (e.g. DOMPurify).
- Add a strict Content-Security-Policy (CSP) to block inline script execution as defense in depth.
- Do not store long-lived session tokens in `localStorage`, which is readable by any script running on the origin (including via XSS); prefer `HttpOnly` cookies.


## Credit

Reported by: Yihan Diao




