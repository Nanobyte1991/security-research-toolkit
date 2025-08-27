# security-research-toolkit
Public resources and tools for external security research &amp; OSINT

# Security Research Toolkit

A curated list of **public resources** for security research and Open Source Intelligence (OSINT).  
This toolkit highlights how attackers — and defenders — can see **external weaknesses** in organisations using only public information.

---

⚠️ **Note**:  
This toolkit uses only **publicly available data**.  
It does not involve intrusive scanning or unauthorised access.  
For demos, use safe domains such as `example.com`.  
Always obtain explicit client consent before demonstrating findings.

---

## 📑 Table of Contents
- [Tools](#-tools)
- [Bonus Tools](#-bonus-tools)
- [Certification & Framework Context](#-certification--framework-context)
- [Comparison Table](#-comparison-table)
- [Demonstrating Weak Links](#-demonstrating-weak-links)
- [CIA Triad Mapping](#-cia-triad-mapping)
- [Responsible Use](#-responsible-use)

---

## 🔧 Tools

### WHOIS Lookup ([who.is](https://who.is))
**What**: Domain registry ownership and lifecycle data.  
**Why**: Accountability and lifecycle risk (e.g., expiry).  
**Shows**: Registrar, name servers, creation/expiry.  
**CIA impact**:  
- **Availability**: Expiry risks outage.  
- **Integrity**: Weak registrar locks risk hijack.  
**Client point**: “Your domain expiry/lock status creates business continuity risks.”

---

### SecurityTrails ([securitytrails.com](https://securitytrails.com))
**What**: Aggregated DNS intelligence.  
**Why**: Map attack surface and legacy exposure.  
**Shows**: Subdomains, DNS records, hosting history.  
**CIA impact**:  
- **Confidentiality**: Hidden services revealed.  
- **Availability**: Misconfigured DNS risks outage.  
**Client point**: “Legacy subdomains remain live; attackers probe these first.”

---

### SSL Labs – Server Test ([ssllabs.com/ssltest](https://www.ssllabs.com/ssltest/))
**What**: TLS/SSL configuration analysis.  
**Why**: Validate encryption posture.  
**Shows**: Certificate details, cipher support, grading.  
**CIA impact**:  
- **Confidentiality & Integrity**: Weak ciphers/HSTS absence expose traffic.  
**Client point**: “TLS grade is below target; session confidentiality is at risk.”

---

### DMARC Inspector ([mxtoolbox.com](https://mxtoolbox.com/DMARC.aspx))
**What**: Email authentication record checks.  
**Why**: Prevent spoofing and phishing.  
**Shows**: DMARC, SPF, DKIM alignment.  
**CIA impact**:  
- **Confidentiality**: Protects against phishing.  
- **Integrity**: Validates sender identity.  
**Client point**: “DMARC set to ‘none’; attackers can spoof your domain.”

---

### Shodan ([shodan.io](https://www.shodan.io))
**What**: Search engine for Internet-exposed services.  
**Why**: Identify unintended exposures.  
**Shows**: Open ports, service versions, TLS certs.  
**CIA impact**:  
- **Confidentiality/Integrity**: Vulnerable services leak or allow tampering.  
- **Availability**: Expands DoS surface.  
**Client point**: “These exposed services increase your attack surface.”

---

### Intelligence X ([intelx.io](https://intelx.io))
**What**: Index of public leaks, pastes, and archives.  
**Why**: Detect credential or document exposure.  
**Shows**: Mentions of company emails and documents.  
**CIA impact**:  
- **Confidentiality**: Leaked credentials enable access.  
**Client point**: “Credentials linked to your domain are visible in leaks.”

---

### UpGuard – External Risk ([upguard.com](https://www.upguard.com))
**What**: External attack surface snapshot.  
**Why**: Executive-level risk overview.  
**Shows**: DNS/TLS/email/auth misconfigs.  
**CIA impact**:  
- **All**: Confidentiality, Integrity, and Availability impacted.  
**Client point**: “These external misconfigs directly affect customers and brand trust.”

---

### VirusTotal – URL Scanner ([virustotal.com](https://www.virustotal.com/gui/home/url))
**What**: Aggregated URL/domain detections.  
**Why**: Triage suspicious links.  
**Shows**: Vendor verdicts, related infrastructure.  
**CIA impact**:  
- **Integrity**: Detects malicious infra.  
**Client point**: “Your URLs are associated with flagged assets; investigate abuse.”

---

### Cisco Talos Reputation ([talosintelligence.com](https://talosintelligence.com/reputation_center/))
**What**: Domain/IP reputation service.  
**Why**: Check trust and deliverability.  
**Shows**: Reputation scores, spam/malware categorisation.  
**CIA impact**:  
- **Availability**: Poor rep disrupts email delivery.  
**Client point**: “Your email may be blocked due to poor reputation.”

---

### AbuseIPDB ([abuseipdb.com](https://www.abuseipdb.com))
**What**: IP abuse reporting database.  
**Why**: Identify compromised/abused IPs.  
**Shows**: Abuse counts, categories, history.  
**CIA impact**:  
- **Availability/Integrity**: Blocklisted IPs disrupt services.  
**Client point**: “This IP is flagged repeatedly; investigate for compromise.”

---

### GreyNoise ([viz.greynoise.io](https://viz.greynoise.io))
**What**: Noise intelligence on scanners.  
**Why**: Distinguish targeted vs. background scanning.  
**Shows**: IP context, tags.  
**CIA impact**:  
- **Availability**: Helps tune defences against noise.  
**Client point**: “This activity is background scanning; adjust alerts accordingly.”

---

### Valimail Domain Checker ([valimail.com](https://www.valimail.com/domain-checker/))
**What**: Email authentication posture checker.  
**Why**: Strengthen trust and deliverability.  
**Shows**: SPF, DKIM, DMARC, BIMI.  
**CIA impact**:  
- **Confidentiality/Integrity**: Stronger email identity assurance.  
**Client point**: “Advance DMARC enforcement; enable BIMI for brand trust.”

---

## 📌 Bonus Tools
- [urlscan.io](https://urlscan.io) — Automated URL scans with screenshots.  
- [crt.sh](https://crt.sh) — Certificate Transparency search.  
- [Wayback Machine](https://web.archive.org) — Historical site snapshots.  

---

## 🛡️ Certification & Framework Context

Even with recognised certifications:

- **Cyber Essentials (CE)** – UK baseline (patching, firewalls, malware, access).  
- **Cyber Essentials Plus (CE+)** – Adds testing but point-in-time only.  
- **ISO/IEC 27001** – ISMS standard; scope-dependent.  
- **SOC 2** – Trust Services Criteria; audits processes, not external exposures.

---

## 📊 Comparison Table

| Framework | What it covers | External gaps these tools reveal |
|-----------|----------------|----------------------------------|
| CE | Patch mgmt, firewalls, malware, access | TLS misconfigs, DNS hygiene, weak email auth |
| CE+ | Adds pen testing (point-in-time) | Continuous monitoring, subdomain drift |
| ISO 27001 | ISMS scope & governance | External exposures outside scope |
| SOC 2 | Trust Services Criteria (audits) | Internet-visible misconfigs, brand/email abuse |

---

## 🔎 Demonstrating Weak Links

With only a **domain, URL, or email**, you can show:
- Registration info & DNS history  
- TLS weaknesses  
- Missing email auth controls  
- Exposed services  
- Reputation problems  
- Leak mentions & scanning traffic  

👉 This is the **attacker’s view** — showing the value of **continuous external monitoring**.

---

## 🔐 CIA Triad Mapping

- **Confidentiality**: Email authentication, leaks, TLS encryption.  
- **Integrity**: Strong TLS/HSTS, DNS accuracy, sender authentication.  
- **Availability**: Attack surface reduction, DNS resilience, reputation management.  

---

## ⚠️ Responsible Use
This toolkit is for **educational and defensive purposes only**.  
Do not use these tools against any domain or system without explicit authorisation.  
Always obtain client consent before demonstrating real-world findings.
