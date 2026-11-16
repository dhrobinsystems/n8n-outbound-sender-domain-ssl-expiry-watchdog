# ⚠️ Disclaimer & Liability Limitation

**Use at your own risk.** The code, workflows, and scripts in this repository (`n8n-outbound-sender-domain-ssl-expiry-watchdog`) are provided for educational and architectural demonstration purposes.

## No Liability

The author and dhRobin Systems accept no responsibility or liability for any direct, indirect, incidental, or consequential damages that result from using, misusing, or deploying these scripts. This includes, without limitation, missed or late certificate expiry warnings, expired certificates on sending, tracking or landing domains, resulting deliverability or reputation loss, false positives or false negatives, blocked requests or abuse reports triggered by inspection traffic, notifications sent to the wrong channel, leaked webhook URLs or tokens, duplicate or unwanted HubSpot or Notion records, service interruptions, and API quota exhaustion.

## No Warranty

All software, n8n JSON blueprints, JavaScript modules and prompts are provided "AS IS", without warranty of any kind, express or implied. This includes, but is not limited to, warranties of merchantability, fitness for a particular purpose, and non-infringement.

No warranty is given that a domain reported as `ok` is secure; that certificate trust evaluated by the n8n host matches what browsers, mail gateways or link scanners will decide; that security headers observed by the watchdog match those served to real visitors; that the SSRF guard covers every private or reserved address range or DNS rebinding technique; that the schedule runs; or that Slack, webhook, HubSpot or Notion deliveries succeed.

## Production Testing Required

Always test thoroughly in an isolated staging environment, with `SANDBOX_MODE=true` and `DRY_RUN=true` enabled, before you inspect live domains or connect live Slack, webhook, HubSpot or Notion credentials. Compare the first live results with an independent check (a browser, `openssl s_client` or your certificate provider's dashboard), confirm that alerts reach the right channel, and keep a second, independent expiry monitor for business-critical domains.

Treat every result as a monitoring signal that a person must verify. This workflow is not a vulnerability scan or a penetration test.

## Third-Party APIs & Compliance

You alone are responsible for complying with the terms of service, rate limits, data privacy regulations (GDPR/CCPA and equivalents), and security policies of Slack, HubSpot, Notion, your webhook receiver, your DNS, hosting, CDN and email service providers, and any connected services. That includes:

- inspecting only domains you own or are explicitly authorised to test;
- keeping the private-target guard enabled unless the instance is dedicated to internal monitoring;
- securing, rotating and restricting access to the Slack webhook URL, alert webhook token, HubSpot private app token, Notion integration token and domain-list token;
- keeping personal data out of domain list fields such as `owner`;
- limiting access to n8n execution data and applying a retention period that matches your policies;
- reviewing every automatically created record.

## No Affiliation

Slack, HubSpot, Notion, Node.js and n8n are trademarks of their respective owners. This project is independent and is not affiliated with, endorsed by, or sponsored by any of them. All domains, IP addresses, certificates, owners and identifiers in the fixtures, sample payloads and pinned data are fictitious or reserved for documentation.

## Not Professional Advice

Nothing in this repository constitutes legal, security, compliance, or financial advice. Consult qualified professionals for your specific circumstances.

---

Released under the MIT License. Copyright (c) 2026 DH Robin (dhRobin Systems). See [LICENSE](LICENSE).

Full text: DISCLAIMER.md · Licensed under the MIT License. License: MIT © 2026 dhRobin Systems · Provided as-is, see the disclaimer.
