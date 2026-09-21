---
name: email-dns
description: "Email, DNS, and identity infrastructure testing — SPF/DKIM/DMARC alignment, SMTP smuggling, header injection, inbound parsing, DNS rebinding, dangling-record takeover, origin disclosure."
---

# Email / DNS / Identity Infrastructure

Email, DNS, and identity infrastructure testing asks whether a mail-authentication, header-parsing, DNS-resolution, or certificate signal carries a **trust decision** that a researcher-controlled mailbox or domain can cross.
Work the **SPF/DKIM/DMARC alignment**, **SMTP smuggling**, **header and template injection**, **inbound parsing**, **DNS rebinding**, **dangling-record takeover**, and **origin disclosure** families once program scope has confirmed that DNS, email, and infrastructure observations are reportable.

## Run this

1. **Confirm scope** — the program scope decides whether DNS, email, or infrastructure findings are reportable; write that decision down first. Done when reportability and the in-scope asset list are recorded before any probe.

2. **Baseline posture** — record SPF, DKIM, DMARC, CAA, DNSSEC, and nameserver answers plus a benign researcher-email delivery header set. Done when every record class has a pre-probe value.

3. **Spoof-context probe** — send a researcher-domain test message to the researcher mailbox and record the authentication-result headers. Done when every spoof-shaped test stays inside your own domain and mailbox, with its result headers captured.

4. **Injection probe** — submit one benign header or template token through a single input field and inspect only the researcher-delivered message and researcher-visible ticket rendering. Done when the reflection is classified as structured header, evaluated template, or absent.

5. **Rebinding probe** — use a researcher domain with a short TTL, record both resolutions, and test exactly one trust decision at low rate. Done when the resolution flip and the Host-validation behavior are both recorded, halting the probe on any non-researcher effect.

6. **Takeover validation** — confirm the dangling record, check service-side claimability with the researcher account, and claim only where scope and service rules permit benign proof. Done when claimability rests on a researcher claim or a vendor-documented claimable fingerprint.

7. **Zone transfer and origin convergence** — run one AXFR or IXFR query against an authorized nameserver target, then require two independent signals (error, header, certificate, historical DNS) to converge on one origin. Done when full zone contents or a refusal are recorded, and origin disclosure waits on two agreeing signals.

## Done when

- Each family tested has a pre-probe baseline (mail-auth records, nameservers, delivery headers) recorded before its probe.

- Every oracle candidate lands on a researcher-owned mailbox, domain, or account, with victim-side effect explicitly absent.

- Takeover, rebinding, and origin claims each rest on a researcher claim or on two independent converging signals.

## Stop conditions

Third-party mailbox effect, production mail-loop risk, unrelated zone data, or customer hostname exposure beyond the oracle.
Halt, retain minimal evidence, clean up researcher artifacts, and report.

## Depth

Field guide: `12_knowledge/email-dns/email-dns.md` — research families, preconditions, oracle catalog, false-positive disambiguation, per-receiver mail-auth semantics, per-hop SMTP normalization, and dangling-DNS tooling references.
