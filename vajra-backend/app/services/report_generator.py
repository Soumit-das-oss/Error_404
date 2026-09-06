import html
from typing import Dict, Any, List


def generate_html_report(case_intel: Dict[str, Any]) -> str:
    """Generate a high-resolution, printable forensic dossier HTML report for an email case."""
    case_id = html.escape(str(case_intel.get("case_id", "N/A")))
    sha256 = html.escape(str(case_intel.get("sha256", "N/A")))
    subject = html.escape(str(case_intel.get("subject") or "No Subject Line"))
    sender = html.escape(str(case_intel.get("sender") or "Unknown"))
    sender_display_name = html.escape(str(case_intel.get("sender_display_name") or "None"))
    recipient = html.escape(str(case_intel.get("recipient") or "Unknown"))
    date_hdr = html.escape(str(case_intel.get("date") or "N/A"))
    message_id = html.escape(str(case_intel.get("message_id") or "N/A"))
    created_at = html.escape(str(case_intel.get("created_at") or "N/A"))
    earliest_public_ip = html.escape(str(case_intel.get("earliest_public_ip") or "None detected"))
    llm_summary = html.escape(str(case_intel.get("llm_summary") or ""))

    risk = case_intel.get("risk", {})
    score = int(risk.get("score", 0))
    verdict = str(risk.get("verdict", "SAFE")).upper()
    penalties = risk.get("itemized_penalties", [])

    auth = case_intel.get("auth", {})
    spf = auth.get("spf", {})
    dkim = auth.get("dkim", {})
    dmarc = auth.get("dmarc", {})

    hops: List[Dict[str, Any]] = case_intel.get("hops", [])

    # Theme colors based on verdict
    if verdict == "CRITICAL":
        badge_bg = "#ef4444"
        badge_border = "#dc2626"
        verdict_color = "#f87171"
    elif verdict == "SUSPICIOUS":
        badge_bg = "#f59e0b"
        badge_border = "#d97706"
        verdict_color = "#fbbf24"
    else:
        badge_bg = "#10b981"
        badge_border = "#059669"
        verdict_color = "#34d399"

    # Build auth status badges
    def auth_badge(status_str: str) -> str:
        s = status_str.upper()
        if s == "PASS":
            return '<span class="status-pill status-pass">PASS</span>'
        elif s in ("FAIL", "SOFTFAIL"):
            return f'<span class="status-pill status-fail">{html.escape(s)}</span>'
        elif s in ("NONE", "MISSING"):
            return f'<span class="status-pill status-warn">{html.escape(s)}</span>'
        else:
            return f'<span class="status-pill status-neutral">{html.escape(s)}</span>'

    # Reverse hop table rows
    hop_rows = []
    if hops:
        for h in hops:
            hop_num = h.get("hop_number", "-")
            ip = html.escape(str(h.get("ip", "-")))
            loc = f"{h.get('city') or 'Unknown'}, {h.get('country') or 'Unknown'}"
            asn_org = html.escape(str(h.get("asn_org") or "-"))
            is_tor = '<span class="status-pill status-fail">TOR EXIT</span>' if h.get("is_tor_exit") else '<span class="status-pill status-pass">CLEAN</span>'
            delay = f"{h.get('delay_seconds'):.1f}s" if h.get("delay_seconds") is not None else "-"
            hop_rows.append(f"""
                <tr>
                    <td style="font-weight: 600; text-align: center;">#{hop_num}</td>
                    <td class="mono">{ip}</td>
                    <td>{loc}</td>
                    <td>{asn_org}</td>
                    <td style="text-align: center;">{is_tor}</td>
                    <td style="text-align: right;">{delay}</td>
                </tr>
            """)
    else:
        hop_rows.append("<tr><td colspan='6' style='text-align: center; color: #94a3b8;'>No public MTA hops identified in header traversal.</td></tr>")

    # Penalties rows
    penalty_rows = []
    if penalties:
        for p in penalties:
            rule = html.escape(str(p.get("rule", "-")))
            pts = f"+{p.get('penalty', 0)}"
            reason = html.escape(str(p.get("reason", "-")))
            penalty_rows.append(f"""
                <tr>
                    <td style="font-weight: 600; color: #f87171;">{rule}</td>
                    <td style="font-weight: bold; color: #ef4444; text-align: center;">{pts}</td>
                    <td style="color: #cbd5e1;">{reason}</td>
                </tr>
            """)
    else:
        penalty_rows.append("<tr><td colspan='3' style='text-align: center; color: #34d399; font-weight: 500;'>Clean Audit: Zero threat penalties triggered.</td></tr>")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VAJRA Forensic Intelligence Dossier - {case_id}</title>
    <!-- Client-side html2pdf.js for direct 1-click PDF generation -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.1/html2pdf.bundle.min.js"></script>
    <style>
        :root {{
            --bg-primary: #0b0f19;
            --bg-card: #131b2e;
            --bg-card-alt: #1a243b;
            --border-color: #243252;
            --text-main: #f1f5f9;
            --text-muted: #94a3b8;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
        }}

        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-main);
            line-height: 1.5;
            padding: 30px 20px;
        }}

        .container {{
            max-width: 1000px;
            margin: 0 auto;
        }}

        .top-bar {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 25px;
            padding-bottom: 15px;
            border-bottom: 1px solid var(--border-color);
        }}

        .brand-logo {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}

        .brand-title {{
            font-size: 24px;
            font-weight: 800;
            letter-spacing: 1.5px;
            color: #ffffff;
        }}

        .brand-title span {{
            color: var(--accent-cyan);
        }}

        .brand-sub {{
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-muted);
        }}

        .btn-print {{
            background: linear-gradient(135deg, #0284c7, #2563eb);
            color: #ffffff;
            border: none;
            padding: 10px 20px;
            font-size: 14px;
            font-weight: 600;
            border-radius: 6px;
            cursor: pointer;
            box-shadow: 0 4px 12px rgba(37, 99, 235, 0.3);
            display: flex;
            align-items: center;
            gap: 8px;
            transition: all 0.2s ease;
        }}

        .btn-print:hover {{
            opacity: 0.9;
            transform: translateY(-1px);
        }}

        .btn-print:disabled {{
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }}

        .action-group {{
            display: flex;
            flex-direction: column;
            align-items: flex-end;
            gap: 6px;
        }}

        .print-fallback-link {{
            font-size: 11px;
            color: var(--text-muted);
            text-decoration: underline;
            cursor: pointer;
            transition: color 0.2s ease;
        }}

        .print-fallback-link:hover {{
            color: var(--accent-cyan);
        }}

        .card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);
        }}

        .card-header {{
            font-size: 15px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--accent-cyan);
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}

        .mono {{
            font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, Courier, monospace;
            font-size: 13px;
            word-break: break-all;
        }}

        /* Grid layouts */
        .grid-2 {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
        }}

        .grid-3 {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 16px;
        }}

        .meta-item {{
            margin-bottom: 10px;
        }}

        .meta-label {{
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-muted);
            margin-bottom: 2px;
        }}

        .meta-val {{
            font-size: 14px;
            color: var(--text-main);
            font-weight: 500;
        }}

        /* Threat Hero Section */
        .threat-banner {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 20px;
            background: var(--bg-card-alt);
            border-radius: 8px;
            border-left: 6px solid {badge_bg};
            margin-bottom: 20px;
        }}

        .threat-score-box {{
            display: flex;
            align-items: baseline;
            gap: 6px;
        }}

        .threat-score-num {{
            font-size: 48px;
            font-weight: 900;
            color: {verdict_color};
            line-height: 1;
        }}

        .threat-score-max {{
            font-size: 18px;
            color: var(--text-muted);
        }}

        .verdict-badge {{
            display: inline-block;
            background-color: {badge_bg};
            color: #ffffff;
            font-size: 14px;
            font-weight: 800;
            letter-spacing: 1.5px;
            padding: 6px 16px;
            border-radius: 50px;
            text-transform: uppercase;
        }}

        .analyst-brief {{
            font-size: 14px;
            line-height: 1.6;
            color: #e2e8f0;
            background: rgba(15, 23, 42, 0.6);
            padding: 16px;
            border-radius: 6px;
            border-left: 4px solid var(--accent-cyan);
        }}

        /* Tables */
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}

        th {{
            background: var(--bg-card-alt);
            color: var(--text-muted);
            text-align: left;
            padding: 10px 14px;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 11px;
            letter-spacing: 0.5px;
            border-bottom: 1px solid var(--border-color);
        }}

        td {{
            padding: 12px 14px;
            border-bottom: 1px solid rgba(36, 50, 82, 0.5);
            vertical-align: middle;
        }}

        tr:last-child td {{
            border-bottom: none;
        }}

        /* Status Pills */
        .status-pill {{
            display: inline-block;
            padding: 3px 8px;
            font-size: 11px;
            font-weight: 700;
            border-radius: 4px;
            text-transform: uppercase;
        }}

        .status-pass {{
            background-color: rgba(16, 185, 129, 0.2);
            color: #34d399;
            border: 1px solid rgba(16, 185, 129, 0.4);
        }}

        .status-fail {{
            background-color: rgba(239, 68, 68, 0.2);
            color: #f87171;
            border: 1px solid rgba(239, 68, 68, 0.4);
        }}

        .status-warn {{
            background-color: rgba(245, 158, 11, 0.2);
            color: #fbbf24;
            border: 1px solid rgba(245, 158, 11, 0.4);
        }}

        .status-neutral {{
            background-color: rgba(148, 163, 184, 0.2);
            color: #cbd5e1;
            border: 1px solid rgba(148, 163, 184, 0.4);
        }}

        .auth-card {{
            background: var(--bg-card-alt);
            padding: 14px;
            border-radius: 6px;
            border: 1px solid var(--border-color);
        }}

        .auth-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }}

        .auth-name {{
            font-weight: 700;
            font-size: 13px;
        }}

        .auth-desc {{
            font-size: 12px;
            color: var(--text-muted);
            line-height: 1.4;
        }}

        .footer {{
            text-align: center;
            font-size: 11px;
            color: var(--text-muted);
            margin-top: 30px;
            padding-top: 15px;
            border-top: 1px solid var(--border-color);
        }}

        /* Print Specific CSS */
        @media print {{
            body {{
                background-color: #ffffff !important;
                color: #0f172a !important;
                padding: 0 !important;
            }}

            .no-print {{
                display: none !important;
            }}

            .card {{
                background: #ffffff !important;
                border: 1px solid #cbd5e1 !important;
                box-shadow: none !important;
                page-break-inside: avoid;
                margin-bottom: 16px !important;
                padding: 16px !important;
            }}

            .brand-title, .brand-title span {{
                color: #0f172a !important;
            }}

            .threat-banner {{
                background: #f8fafc !important;
                border: 1px solid #cbd5e1 !important;
                border-left: 6px solid {badge_bg} !important;
            }}

            .meta-val, .mono {{
                color: #0f172a !important;
            }}

            th {{
                background: #f1f5f9 !important;
                color: #334155 !important;
            }}

            td {{
                color: #1e293b !important;
                border-bottom: 1px solid #e2e8f0 !important;
            }}

            .auth-card {{
                background: #f8fafc !important;
                border: 1px solid #cbd5e1 !important;
            }}

            .analyst-brief {{
                background: #f8fafc !important;
                color: #1e293b !important;
                border: 1px solid #cbd5e1 !important;
                border-left: 4px solid var(--accent-blue) !important;
            }}
        }}
    </style>
</head>
<body>
    <div class="container" id="report-container">
        <!-- Top Action Bar -->
        <div class="top-bar" id="action-bar">
            <div class="brand-logo">
                <div>
                    <div class="brand-title">VAJRA <span>FORENSICS</span></div>
                    <div class="brand-sub">SIH26106 Email Threat Intelligence Platform</div>
                </div>
            </div>
            <div class="action-group no-print">
                <button id="btn-download-pdf" class="btn-print" onclick="downloadDirectPdf()">
                    <svg width="16" height="16" fill="currentColor" viewBox="0 0 16 16">
                        <path d="M.5 9.9a.5.5 0 0 1 .5.5v2.5a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-2.5a.5.5 0 0 1 1 0v2.5a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2v-2.5a.5.5 0 0 1 .5-.5z"/>
                        <path d="M7.646 11.854a.5.5 0 0 0 .708 0l3-3a.5.5 0 0 0-.708-.708L8.5 10.293V1.5a.5.5 0 0 0-1 0v8.793L5.354 8.146a.5.5 0 1 0-.708.708l3 3z"/>
                    </svg>
                    Download PDF Report
                </button>
                <a href="javascript:void(0)" onclick="window.print()" class="print-fallback-link">or use Browser Print</a>
            </div>
        </div>

        <!-- Threat Score & Executive Summary -->
        <div class="card">
            <div class="card-header">
                <span>Threat Verdict & Executive Briefing</span>
                <span style="font-size: 12px; color: var(--text-muted); font-weight: normal;">Case Dossier: {case_id}</span>
            </div>

            <div class="threat-banner">
                <div>
                    <div class="threat-score-box">
                        <span class="threat-score-num">{score}</span>
                        <span class="threat-score-max">/ 100</span>
                    </div>
                    <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">Computed Forensic Risk Index</div>
                </div>
                <div>
                    <span class="verdict-badge">{verdict}</span>
                </div>
            </div>

            <div class="analyst-brief">
                <strong>Cyber Threat Analyst Assessment:</strong><br>
                {llm_summary}
            </div>
        </div>

        <!-- Chain of Custody & Evidence Headers -->
        <div class="card">
            <div class="card-header">Cryptographic Chain of Custody</div>
            <div class="grid-2">
                <div>
                    <div class="meta-item">
                        <div class="meta-label">Subject</div>
                        <div class="meta-val">{subject}</div>
                    </div>
                    <div class="meta-item">
                        <div class="meta-label">Envelope From</div>
                        <div class="meta-val mono">{sender}</div>
                    </div>
                    <div class="meta-item">
                        <div class="meta-label">Display Name</div>
                        <div class="meta-val">{sender_display_name}</div>
                    </div>
                    <div class="meta-item">
                        <div class="meta-label">Recipient</div>
                        <div class="meta-val mono">{recipient}</div>
                    </div>
                </div>
                <div>
                    <div class="meta-item">
                        <div class="meta-label">Evidence SHA-256 Hash</div>
                        <div class="meta-val mono" style="color: var(--accent-cyan);">{sha256}</div>
                    </div>
                    <div class="meta-item">
                        <div class="meta-label">Origin Entry MTA IP</div>
                        <div class="meta-val mono">{earliest_public_ip}</div>
                    </div>
                    <div class="meta-item">
                        <div class="meta-label">Message-ID</div>
                        <div class="meta-val mono">{message_id}</div>
                    </div>
                    <div class="meta-item">
                        <div class="meta-label">Investigation Timestamp (UTC)</div>
                        <div class="meta-val">{created_at}</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Protocol Authentication Matrix -->
        <div class="card">
            <div class="card-header">Protocol Authentication Matrix</div>
            <div class="grid-3">
                <div class="auth-card">
                    <div class="auth-header">
                        <span class="auth-name">SPF Audit</span>
                        {auth_badge(str(spf.get('status', 'NONE')))}
                    </div>
                    <div class="auth-desc">{html.escape(str(spf.get('details', 'No details')))}</div>
                </div>

                <div class="auth-card">
                    <div class="auth-header">
                        <span class="auth-name">DKIM Crypto</span>
                        {auth_badge(str(dkim.get('status', 'NONE')))}
                    </div>
                    <div class="auth-desc">{html.escape(str(dkim.get('details', 'No details')))}</div>
                </div>

                <div class="auth-card">
                    <div class="auth-header">
                        <span class="auth-name">DMARC Policy</span>
                        {auth_badge(str(dmarc.get('status', 'NONE')))}
                    </div>
                    <div class="auth-desc">
                        Policy: <strong>{html.escape(str(dmarc.get('policy', 'missing')))}</strong><br>
                        {html.escape(str(dmarc.get('details', 'No details')))}
                    </div>
                </div>
            </div>
        </div>

        <!-- Reverse Hop Traversal -->
        <div class="card">
            <div class="card-header">Chronological Reverse MTA Hop Traversal (Bottom-Up)</div>
            <table>
                <thead>
                    <tr>
                        <th style="width: 60px; text-align: center;">Hop</th>
                        <th>Host IP Address</th>
                        <th>Resolved Geolocation</th>
                        <th>ASN / Infrastructure</th>
                        <th style="text-align: center;">Tor Node</th>
                        <th style="text-align: right;">Delay</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(hop_rows)}
                </tbody>
            </table>
        </div>

        <!-- Itemized Penalties -->
        <div class="card">
            <div class="card-header">Itemized Deterministic Risk Deductions</div>
            <table>
                <thead>
                    <tr>
                        <th style="width: 250px;">Trigger Rule</th>
                        <th style="width: 80px; text-align: center;">Penalty</th>
                        <th>Forensic Justification</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(penalty_rows)}
                </tbody>
            </table>
        </div>

        <div class="footer">
            VAJRA Forensic Platform &bull; Smart India Hackathon 2026 Problem Statement SIH26106 &bull; Certified Evidence Dossier
        </div>
    </div>

    <!-- 1-Click Direct Client-Side PDF Generation Script -->
    <script>
        function downloadDirectPdf() {{
            const actionBar = document.getElementById('action-bar');
            const btn = document.getElementById('btn-download-pdf');
            const originalHtml = btn.innerHTML;

            btn.innerHTML = 'Rendering PDF...';
            btn.disabled = true;
            actionBar.style.display = 'none';

            const element = document.getElementById('report-container');
            const opt = {{
                margin: 10,
                filename: 'VAJRA-Forensic-Dossier-{case_id}.pdf',
                image: {{ type: 'jpeg', quality: 0.98 }},
                html2canvas: {{ scale: 2, useCORS: true, logging: false }},
                jsPDF: {{ unit: 'mm', format: 'a4', orientation: 'portrait' }}
            }};

            html2pdf().set(opt).from(element).save().then(function() {{
                actionBar.style.display = 'flex';
                btn.innerHTML = originalHtml;
                btn.disabled = false;
            }}).catch(function(err) {{
                console.error('html2pdf export error:', err);
                actionBar.style.display = 'flex';
                btn.innerHTML = originalHtml;
                btn.disabled = false;
                window.print();
            }});
        }}
    </script>
</body>
</html>
"""


def generate_404_html(case_id: str) -> str:
    """Generate professional cyber-themed 404 page when a forensic case ID is missing."""
    safe_case = html.escape(case_id)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Case Not Found - VAJRA Forensics</title>
    <style>
        body {{
            background: #0b0f19;
            color: #f1f5f9;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
            padding: 20px;
        }}
        .box {{
            background: #131b2e;
            border: 1px solid #243252;
            border-radius: 10px;
            padding: 40px;
            max-width: 500px;
            text-align: center;
            box-shadow: 0 4px 20px rgba(0,0,0,0.4);
        }}
        h1 {{
            color: #ef4444;
            font-size: 28px;
            margin-bottom: 12px;
        }}
        p {{
            color: #94a3b8;
            font-size: 14px;
            line-height: 1.6;
            margin-bottom: 20px;
        }}
        .code {{
            font-family: monospace;
            background: #1e293b;
            padding: 4px 8px;
            border-radius: 4px;
            color: #06b6d4;
        }}
        a {{
            color: #38bdf8;
            text-decoration: none;
            font-weight: 600;
        }}
        a:hover {{
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="box">
        <h1>Forensic Case Not Found</h1>
        <p>The requested forensic investigation case <span class="code">{safe_case}</span> was not found in the VAJRA evidence registry.</p>
        <p>Ensure the case ID was accurately entered or upload a new email for forensic examination.</p>
        <a href="/docs">Return to API Documentation</a>
    </div>
</body>
</html>
"""
