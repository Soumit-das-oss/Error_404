export const mockScanData = {
  score: 88,
  status: "CRITICAL RISK",
  subStatus: "Sender Spoofing & Phishing Detected",
  indicators: [
    { label: "Urgency Manipulation", type: "amber" },
    { label: "Authority Spoofing", type: "rose" },
    { label: "Credential Harvesting", type: "rose" }
  ],
  auth: {
    spf: { pass: false, detail: "Sender IP unauthorized" },
    dkim: { pass: false, detail: "No valid cryptographic signature" },
    dmarc: { pass: false, detail: "Strict reject policy triggered" }
  },
  nlp: {
    verdict: "High-level threat breakdown explaining psychological vectors in plain English. The email uses urgency, fear of account loss, and authority spoofing to coerce the recipient into clicking a malicious link.",
    ip: "45.83.66.12",
    isTor: true
  },
  trace: [
    { label: "Origin: Tor Node", ip: "45.83.66.12", geo: "RU", type: "danger" },
    { label: "Relay: Frankfurt Proxy", ip: "94.130.23.89", geo: "DE", type: "warn" },
    { label: "Target: MX Gateway", ip: "10.0.0.5", geo: "LOCAL", type: "safe" }
  ],
  headers: `Received: from mail.secure-update-bankk.ru (mail.secure-update-bankk.ru [45.83.66.12])
    by mx.yourmail.com with ESMTP id x7si987654xyz.21.2024.03.15
    for <you@yourmail.com>; Fri, 15 Mar 2024 11:48:22 -0700 (PDT)
Received-SPF: FAIL (google.com: domain of noreply@secure-update-bankk.ru does NOT
    designate 45.83.66.12 as permitted sender) client-ip=45.83.66.12;
Authentication-Results: mx.yourmail.com;
   dkim=FAIL (no signature found) header.i=@secure-update-bankk.ru;
   spf=FAIL (google.com: domain of noreply@secure-update-bankk.ru does NOT
           designate 45.83.66.12 as permitted sender)
           smtp.mailfrom=noreply@secure-update-bankk.ru;
   dmarc=FAIL (p=REJECT sp=REJECT dis=REJECTED) header.from=secure-update-bankk.ru
X-Forwarded-For: 45.83.66.12, 94.130.23.89
From: Bank Security Team <noreply@secure-update-bankk.ru>
To: you@yourmail.com
Subject: URGENT: Your account has been temporarily suspended
Date: Fri, 15 Mar 2024 11:47:58 -0700
Message-ID: <MSG-2024-D9X7K@secure-update-bankk.ru>`
};
