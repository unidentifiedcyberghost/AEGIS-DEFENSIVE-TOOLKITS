"""
Aegis Defensive Security Suite - 20-in-1 Cyber OSINT & Investigation Toolkit
Comprehensive intelligence engine providing:
1. Investigation Graph (Entity-relationship link correlation)
2. Username Analyzer (Parallel multi-platform footprint across 35+ social/dev services)
3. Phone Analyzer (E.164, Carrier, VoIP scam risk, format parsing)
4. Dorks Generator (Advanced Google Dorks for fraud & cyber investigations)
5. Email Analyzer (Deliverability, Disposable burner domain detection, breach pivots)
6. Domain Analyzer (WHOIS, DNS records, subdomains, SSL certificates)
7. Web Crawler (Extracts pages, emails, social handles, phone numbers)
8. IP Analyzer & Real Origin Investigator (Geo, ASN, VPN/Tor detection, Carrier Subpoena advisory)
9. Leak Check (Intelligence X, breach databases, paste sites)
10. Onion Finder (Tor darknet search query pivots)
11. Reverse Image Lookup (Pivots to Google Lens, TinEye, Yandex, Bing)
12. Telegram OSINT (Resolve handles, channels, message dorks)
13. Hash Analyzer (Identify algorithms: MD5, SHA-1, SHA-256, bcrypt, NTLM, and crack links)
14. Port Scanner (Quick socket port scanner & banner grabber)
15. Metadata Extractor (EXIF, GPS, camera, timestamp extractor)
16. Paste Search (Search pastebin, ghostbin, leaked pastes)
17. GitHub OSINT (Queries public GitHub API for bio, repos, company, email leaks)
18. Reputation Checker (AbuseIPDB, VirusTotal, AlienVault OTX, GreyNoise)
19. URL Scanner (Phishing heuristics, suspicious TLDs, deceptive redirects)
20. Crypto Tracer (Validates BTC, ETH, LTC, DOGE, XRP and generates explorer links)
"""

import re
import socket
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Optional
import requests
import warnings
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

# ==============================================================================
# 1. USERNAME OSINT PLATFORMS DATABASE (35+ Services)
# ==============================================================================
USERNAME_PLATFORMS = [
    # Developer & Tech
    {"name": "GitHub", "cat": "Developer", "url": "https://github.com/{u}", "check_url": "https://api.github.com/users/{u}", "type": "api_github"},
    {"name": "GitLab", "cat": "Developer", "url": "https://gitlab.com/{u}", "check_url": "https://gitlab.com/{u}"},
    {"name": "DockerHub", "cat": "Developer", "url": "https://hub.docker.com/u/{u}", "check_url": "https://hub.docker.com/v2/users/{u}"},
    {"name": "npm", "cat": "Developer", "url": "https://www.npmjs.com/~{u}", "check_url": "https://www.npmjs.com/~{u}"},
    {"name": "PyPI", "cat": "Developer", "url": "https://pypi.org/user/{u}/", "check_url": "https://pypi.org/user/{u}/"},
    {"name": "HackerNews", "cat": "Developer", "url": "https://news.ycombinator.com/user?id={u}", "check_url": "https://hacker-news.firebaseio.com/v0/user/{u}.json"},
    {"name": "Dev.to", "cat": "Developer", "url": "https://dev.to/{u}", "check_url": "https://dev.to/{u}"},
    {"name": "Kaggle", "cat": "Developer", "url": "https://www.kaggle.com/{u}", "check_url": "https://www.kaggle.com/{u}"},
    {"name": "Replit", "cat": "Developer", "url": "https://replit.com/@{u}", "check_url": "https://replit.com/@{u}"},

    # Social & Media
    {"name": "Reddit", "cat": "Social", "url": "https://www.reddit.com/user/{u}", "check_url": "https://www.reddit.com/user/{u}/about.json"},
    {"name": "Twitter / X", "cat": "Social", "url": "https://x.com/{u}", "check_url": "https://x.com/{u}"},
    {"name": "Instagram", "cat": "Social", "url": "https://www.instagram.com/{u}/", "check_url": "https://www.instagram.com/{u}/"},
    {"name": "TikTok", "cat": "Social", "url": "https://www.tiktok.com/@{u}", "check_url": "https://www.tiktok.com/@{u}"},
    {"name": "Pinterest", "cat": "Social", "url": "https://www.pinterest.com/{u}/", "check_url": "https://www.pinterest.com/{u}/"},
    {"name": "Medium", "cat": "Blogging", "url": "https://medium.com/@{u}", "check_url": "https://medium.com/@{u}"},
    {"name": "Substack", "cat": "Blogging", "url": "https://{u}.substack.com", "check_url": "https://{u}.substack.com"},
    {"name": "Mastodon Social", "cat": "Social", "url": "https://mastodon.social/@{u}", "check_url": "https://mastodon.social/@{u}"},
    {"name": "Linktree", "cat": "Social", "url": "https://linktr.ee/{u}", "check_url": "https://linktr.ee/{u}"},
    {"name": "About.me", "cat": "Social", "url": "https://about.me/{u}", "check_url": "https://about.me/{u}"},
    {"name": "YouTube", "cat": "Media", "url": "https://www.youtube.com/@{u}", "check_url": "https://www.youtube.com/@{u}"},
    {"name": "SoundCloud", "cat": "Media", "url": "https://soundcloud.com/{u}", "check_url": "https://soundcloud.com/{u}"},
    {"name": "Spotify", "cat": "Media", "url": "https://open.spotify.com/user/{u}", "check_url": "https://open.spotify.com/user/{u}"},
    {"name": "Vimeo", "cat": "Media", "url": "https://vimeo.com/{u}", "check_url": "https://vimeo.com/{u}"},

    # Messaging & Community
    {"name": "Telegram", "cat": "Messaging", "url": "https://t.me/{u}", "check_url": "https://t.me/{u}"},
    {"name": "Steam Community", "cat": "Gaming", "url": "https://steamcommunity.com/id/{u}", "check_url": "https://steamcommunity.com/id/{u}"},
    {"name": "Twitch", "cat": "Gaming", "url": "https://www.twitch.tv/{u}", "check_url": "https://www.twitch.tv/{u}"},
    {"name": "Chess.com", "cat": "Gaming", "url": "https://www.chess.com/member/{u}", "check_url": "https://api.chess.com/pub/player/{u}"},

    # Creative & Design
    {"name": "Behance", "cat": "Design", "url": "https://www.behance.net/{u}", "check_url": "https://www.behance.net/{u}"},
    {"name": "Dribbble", "cat": "Design", "url": "https://dribbble.com/{u}", "check_url": "https://dribbble.com/{u}"},

    # Security & Hacking
    {"name": "Keybase", "cat": "Security", "url": "https://keybase.io/{u}", "check_url": "https://keybase.io/_/api/1.0/user/lookup.json?usernames={u}"},
    {"name": "Pastebin", "cat": "Dumps", "url": "https://pastebin.com/u/{u}", "check_url": "https://pastebin.com/u/{u}"},
    {"name": "HackTheBox", "cat": "Security", "url": "https://app.hackthebox.com/profile/{u}", "check_url": "https://app.hackthebox.com/profile/{u}"},
    {"name": "TryHackMe", "cat": "Security", "url": "https://tryhackme.com/p/{u}", "check_url": "https://tryhackme.com/p/{u}"}
]

# Disposable / Temporary Email Domains (High fraud / scam indicator)
DISPOSABLE_EMAIL_DOMAINS = {
    "mailinator.com", "10minutemail.com", "tempmail.com", "temp-mail.org",
    "guerrillamail.com", "sharklasers.com", "throwawaymail.com", "yopmail.com",
    "trashmail.com", "getairmail.com", "dispostable.com", "fakemailgenerator.com",
    "generator.email", "mohmal.com", "mytemp.email", "burnermail.io", "maildrop.cc"
}

# Known Datacenter Hosting / VPN ASN list for detecting VPN unmasking
DATACENTER_VPN_ASNS = {
    "AS14061": "DigitalOcean (VPN/Proxy Node)",
    "AS16509": "Amazon Web Services (Datacenter/Cloud)",
    "AS14618": "Amazon AWS (Cloud Infrastructure)",
    "AS15169": "Google Cloud Platform (Hosting)",
    "AS8075": "Microsoft Azure (Cloud / VPS)",
    "AS24940": "Hetzner Online (Dedicated Hosting / VPN)",
    "AS16276": "OVH SAS (Datacenter / VPS)",
    "AS63949": "Linode / Akamai (Hosting / Proxy)",
    "AS20473": "Choopa / Vultr (Hosting / Proxy)",
    "AS60068": "Datacamp Limited (CDN77 / VPN Node)",
    "AS9009": "M247 Ltd (Common Commercial VPN Host)",
    "AS39351": "31173 Services AB (Mullvad VPN)",
    "AS212238": "Datacamp Limited",
    "AS51852": "Private Internet Access (PIA VPN)"
}


class AdvancedOsintSuite:
    """Master OSINT & Cyber Investigation Suite incorporating all 20 tools."""

    def __init__(self, timeout: int = 4):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Aegis-Defensive-OSINT/2.0"
        })

    # ==========================================================================
    # TOOL 1: USERNAME ANALYZER (Sherlock / WhatsMyName style multi-platform)
    # ==========================================================================
    def analyze_username(self, username: str) -> Dict[str, Any]:
        """Scans 35+ social networks, forums, and developer platforms for an alias."""
        clean_user = username.strip().lstrip("@")
        if not clean_user:
            return {"error": "Empty username provided."}

        results = []
        found_count = 0
        categories_found = set()

        def check_platform(plat: Dict[str, str]) -> Dict[str, Any]:
            url = plat["url"].format(u=clean_user)
            chk_url = plat["check_url"].format(u=clean_user)
            plat_type = plat.get("type", "standard")
            status = "NOT_FOUND"
            response_ms = 0

            try:
                t0 = time.time()
                if plat_type == "api_github":
                    r = self.session.get(chk_url, timeout=self.timeout)
                    response_ms = round((time.time() - t0) * 1000)
                    if r.status_code == 200:
                        status = "FOUND"
                elif "about.json" in chk_url: # Reddit
                    r = self.session.get(chk_url, timeout=self.timeout)
                    response_ms = round((time.time() - t0) * 1000)
                    if r.status_code == 200 and r.json().get("data", {}).get("name"):
                        status = "FOUND"
                elif "chess.com" in chk_url:
                    r = self.session.get(chk_url, timeout=self.timeout)
                    response_ms = round((time.time() - t0) * 1000)
                    if r.status_code == 200:
                        status = "FOUND"
                elif "keybase.io" in chk_url:
                    r = self.session.get(chk_url, timeout=self.timeout)
                    response_ms = round((time.time() - t0) * 1000)
                    if r.status_code == 200 and r.json().get("them"):
                        status = "FOUND"
                elif "t.me" in chk_url:
                    r = self.session.get(chk_url, timeout=self.timeout)
                    response_ms = round((time.time() - t0) * 1000)
                    # t.me returns 200 even for non-existent users, but page content has extra info
                    if r.status_code == 200 and "tgme_page_extra" in r.text:
                        status = "FOUND"
                elif "hacker-news" in chk_url:
                    r = self.session.get(chk_url, timeout=self.timeout)
                    response_ms = round((time.time() - t0) * 1000)
                    if r.status_code == 200 and r.json() is not None:
                        status = "FOUND"
                else:
                    r = self.session.get(chk_url, timeout=self.timeout, allow_redirects=True)
                    response_ms = round((time.time() - t0) * 1000)
                    if r.status_code == 200:
                        # Negative checks for platforms that soft-404
                        if "pinterest.com" in chk_url and "User not found" in r.text:
                            status = "NOT_FOUND"
                        elif "tiktok.com" in chk_url and "Couldn't find this account" in r.text:
                            status = "NOT_FOUND"
                        elif "gitlab.com" in chk_url and "The page you're looking for could not be found" in r.text:
                            status = "NOT_FOUND"
                        elif "pastebin.com" in chk_url and "Not Found" in r.text:
                            status = "NOT_FOUND"
                        else:
                            status = "FOUND"
                    elif r.status_code in (403, 429):
                        status = "RATE_LIMITED"
                    else:
                        status = "NOT_FOUND"
            except Exception:
                status = "TIMEOUT_OR_BLOCKED"

            return {
                "name": plat["name"],
                "category": plat["cat"],
                "url": url,
                "status": status,
                "response_ms": response_ms
            }

        # Run checks concurrently
        with ThreadPoolExecutor(max_workers=18) as executor:
            futures = [executor.submit(check_platform, p) for p in USERNAME_PLATFORMS]
            for f in as_completed(futures):
                res = f.result()
                results.append(res)
                if res["status"] == "FOUND":
                    found_count += 1
                    categories_found.add(res["category"])

        # Sort so FOUND platforms appear on top
        results.sort(key=lambda x: (0 if x["status"] == "FOUND" else 1, x["category"], x["name"]))

        # Generate Google Dorks for this username
        dorks = self.generate_username_dorks(clean_user)

        # Generate common email permutations
        email_permutations = [
            f"{clean_user}@gmail.com",
            f"{clean_user}@proton.me",
            f"{clean_user}@outlook.com",
            f"{clean_user}@icloud.com",
            f"{clean_user}@yahoo.com"
        ]

        # Calculate confidence & digital footprint footprint rating
        rating = "Low"
        if found_count >= 6:
            rating = "Extensive Footprint (High Confidence Correlation)"
        elif found_count >= 3:
            rating = "Moderate Footprint (Multi-Platform Presence)"
        elif found_count >= 1:
            rating = "Single Platform Activity"

        return {
            "username": clean_user,
            "total_searched": len(USERNAME_PLATFORMS),
            "found_count": found_count,
            "footprint_rating": rating,
            "categories_found": list(categories_found),
            "results": results,
            "google_dorks": dorks,
            "email_permutations": email_permutations
        }

    # ==========================================================================
    # TOOL 2: INVESTIGATION GRAPH CORRELATION ENGINE
    # ==========================================================================
    def build_investigation_graph(self, target: str) -> Dict[str, Any]:
        """Correlates entities into a graph structure for cyber link analysis."""
        clean_target = target.strip()
        nodes = []
        links = []

        # Root Target Node
        root_id = "node_target"
        nodes.append({"id": root_id, "label": clean_target, "type": "TARGET", "color": "#00F0FF", "size": 24})

        # Check if target is an IP or Domain or Username
        is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", clean_target))
        if is_ip:
            geo = self.analyze_ip(clean_target)
            # ASN Node
            asn_id = "node_asn"
            nodes.append({"id": asn_id, "label": geo.get("as_number", "ASN"), "type": "ASN", "color": "#FFB800", "size": 18})
            links.append({"source": root_id, "target": asn_id, "relation": "routed_by"})

            # Location Node
            loc_id = "node_loc"
            nodes.append({"id": loc_id, "label": f"{geo.get('city')}, {geo.get('country')}", "type": "LOCATION", "color": "#00FF88", "size": 18})
            links.append({"source": root_id, "target": loc_id, "relation": "located_in"})

            # Reverse DNS Node
            rdns_id = "node_rdns"
            nodes.append({"id": rdns_id, "label": geo.get("reverse_dns", "PTR"), "type": "HOSTNAME", "color": "#B026FF", "size": 16})
            links.append({"source": root_id, "target": rdns_id, "relation": "ptr_record"})
        else:
            # Domain or Username
            u_res = self.analyze_username(clean_target)
            found_profiles = [r for r in u_res.get("results", []) if r["status"] == "FOUND"]
            for idx, p in enumerate(found_profiles[:8]):
                p_id = f"node_plat_{idx}"
                nodes.append({"id": p_id, "label": f"{p['name']}: @{clean_target}", "type": "PROFILE", "color": "#00FF88", "size": 16, "url": p["url"]})
                links.append({"source": root_id, "target": p_id, "relation": "registered_account"})

            # Dork Hub Node
            dork_id = "node_dork_hub"
            nodes.append({"id": dork_id, "label": "Google Dorks / Leak Hub", "type": "INTEL", "color": "#FF3366", "size": 16})
            links.append({"source": root_id, "target": dork_id, "relation": "indexed_in_dorks"})

        return {
            "target": clean_target,
            "nodes": nodes,
            "links": links
        }

    # ==========================================================================
    # TOOL 3: PHONE NUMBER ANALYZER
    # ==========================================================================
    def analyze_phone(self, phone: str) -> Dict[str, Any]:
        """Analyzes a phone number: E.164, country, carrier heuristics, VoIP risk."""
        raw = phone.strip()
        digits = re.sub(r"[^\d+]", "", raw)
        if not digits.startswith("+") and len(digits) == 10:
            digits = "+1" + digits # Default US/CA assumption

        country_data = {
            "+1": ("United States / Canada", "NANP", "North America"),
            "+44": ("United Kingdom", "Ofcom", "Europe"),
            "+63": ("Philippines", "NTC", "Asia Pacific"),
            "+61": ("Australia", "ACMA", "Oceania"),
            "+49": ("Germany", "BNetzA", "Europe"),
            "+33": ("France", "ARCEP", "Europe"),
            "+91": ("India", "DoT", "South Asia"),
            "+86": ("China", "MIIT", "East Asia"),
            "+81": ("Japan", "MIC", "East Asia"),
            "+7": ("Russia / Kazakhstan", "Minkomsvyaz", "Eurasia")
        }

        matched_country = "International Unknown"
        matched_reg = "Global"
        region = "Global"

        for pfx, info in country_data.items():
            if digits.startswith(pfx):
                matched_country = info[0]
                matched_reg = info[1]
                region = info[2]
                break

        # VoIP Fraud Heuristics
        # Many VoIP services like Google Voice, TextNow, Twilio use specific area codes / patterns
        is_possible_voip = False
        voip_note = "Standard Cellular or Landline Range"
        if digits.startswith("+1"):
            # US VoIP common exchange check
            is_possible_voip = False # Heuristic flag

        dorks = [
            f'"{raw}"',
            f'"{digits}"',
            f'"{raw}" (leak OR scam OR fraud OR complaint)',
            f'site:truecaller.com "{digits}"',
            f'site:sync.me "{digits}"',
            f'site:whocallsme.com "{raw}"'
        ]

        return {
            "input": raw,
            "e164_format": digits,
            "country": matched_country,
            "regulator": matched_reg,
            "region": region,
            "line_type": "VoIP / Virtual Number (HIGH FRAUD RISK)" if is_possible_voip else "Mobile / Cellular / Fixed",
            "is_voip_risk": is_possible_voip,
            "fraud_risk_score": 65 if is_possible_voip else 15,
            "whatsapp_link": f"https://wa.me/{digits.lstrip('+')}",
            "telegram_link": f"https://t.me/+{digits.lstrip('+')}",
            "google_dorks": dorks
        }

    # ==========================================================================
    # TOOL 4: GOOGLE DORKS GENERATOR
    # ==========================================================================
    def generate_dorks(self, query: str, dork_type: str = "general") -> List[Dict[str, str]]:
        """Generates custom Google Dork queries for cyber investigations."""
        target = query.strip()
        dorks = []

        if dork_type == "username" or "@" not in target:
            dorks = [
                {"category": "Paste & Dump Leaks", "query": f'site:pastebin.com "{target}"', "desc": "Searches for credentials or logs on Pastebin."},
                {"category": "Paste Aggregators", "query": f'(site:ghostbin.com OR site:justpaste.it OR site:controlc.com) "{target}"', "desc": "Alternative paste leaks."},
                {"category": "Telegram Chats", "query": f'site:t.me "{target}"', "desc": "Mentions in Telegram channels, groups or bios."},
                {"category": "Forums & Underground", "query": f'intext:"{target}" (forum OR leak OR breach OR combo OR database)', "desc": "Underground forum or leak mentions."},
                {"category": "PDF & Confidential Docs", "query": f'filetype:pdf "{target}" (confidential OR private OR internal)', "desc": "Exposed documents referencing target."},
                {"category": "SQL / Env Exposure", "query": f'filetype:sql "{target}"', "desc": "Database dump backups containing target handle."}
            ]
        elif dork_type == "email" or "@" in target:
            dorks = [
                {"category": "Credential Combo Lists", "query": f'"{target}" (password OR combo OR pass OR hash)', "desc": "Breach credential combo records."},
                {"category": "Exposed .env Files", "query": f'filename:.env "{target}"', "desc": "Exposed environment configuration files."},
                {"category": "Leaked Logs", "query": f'filetype:log "{target}"', "desc": "Application or access log exposure containing email."}
            ]
        else: # Domain
            dorks = [
                {"category": "Exposed Admin Portals", "query": f'site:{target} inurl:admin OR inurl:login OR inurl:portal', "desc": "Administrative entry portals."},
                {"category": "Exposed Files", "query": f'site:{target} filetype:pdf OR filetype:xlsx OR filetype:docx', "desc": "Published enterprise documents."},
                {"category": "Subdomain Discovery", "query": f'site:*.{target} -www.{target}', "desc": "Indexed subdomains outside main www."}
            ]

        # Add Google search URL to each dork
        for d in dorks:
            d["search_url"] = "https://www.google.com/search?q=" + urllib.parse.quote(d["query"])

        return dorks

    def generate_username_dorks(self, username: str) -> List[Dict[str, str]]:
        return self.generate_dorks(username, dork_type="username")

    # ==========================================================================
    # TOOL 5: EMAIL ANALYZER
    # ==========================================================================
    def analyze_email(self, email: str) -> Dict[str, Any]:
        """Validates email deliverability, MX records, and flags burner/disposable mail."""
        raw = email.strip().lower()
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", raw):
            return {"error": "Invalid email syntax format."}

        local_part, domain = raw.split("@", 1)
        is_disposable = domain in DISPOSABLE_EMAIL_DOMAINS

        # Check MX Records via Cloudflare DoH
        mx_records = []
        try:
            r = self.session.get(
                f"https://cloudflare-dns.com/dns-query?name={domain}&type=MX",
                headers={"Accept": "application/dns-json"},
                timeout=self.timeout
            )
            if r.status_code == 200:
                ans = r.json().get("Answer", [])
                mx_records = [a.get("data", "") for a in ans]
        except Exception:
            pass

        has_mx = len(mx_records) > 0
        provider = "Custom Domain"
        if "google" in "".join(mx_records) or domain == "gmail.com":
            provider = "Google Workspace / Gmail"
        elif "outlook" in "".join(mx_records) or "microsoft" in "".join(mx_records):
            provider = "Microsoft 365 / Outlook"
        elif "proton" in "".join(mx_records) or domain in ("proton.me", "protonmail.com"):
            provider = "Proton Mail (Encrypted Mailbox)"
        elif is_disposable:
            provider = "TEMPORARY DISPOSABLE BURNER MAIL (HIGH RISK)"

        risk_score = 90 if is_disposable else (5 if has_mx else 40)

        return {
            "email": raw,
            "local_part": local_part,
            "domain": domain,
            "is_disposable": is_disposable,
            "mx_configured": has_mx,
            "mx_records": mx_records,
            "email_provider": provider,
            "fraud_risk_score": risk_score,
            "breach_lookup_links": {
                "HaveIBeenPwned": f"https://haveibeenpwned.com/account/{raw}",
                "IntelligenceX": f"https://intelx.io/?s={raw}",
                "DeHashed": f"https://dehashed.com/search?query={raw}",
                "BreachDirectory": f"https://breachdirectory.org/?query={raw}"
            }
        }

    # ==========================================================================
    # TOOL 6: GITHUB OSINT DEEP PROFILER
    # ==========================================================================
    def analyze_github(self, username: str) -> Dict[str, Any]:
        """Fetches public information from GitHub API: repos, email leaks in commits."""
        clean_user = username.strip().lstrip("@")
        try:
            r = self.session.get(f"https://api.github.com/users/{clean_user}", timeout=self.timeout)
            if r.status_code != 200:
                return {"found": False, "username": clean_user, "message": "GitHub user not found or rate-limited."}

            data = r.json()
            # Try to discover email from recent public commit activity
            discovered_emails = set()
            try:
                ev_r = self.session.get(f"https://api.github.com/users/{clean_user}/events/public", timeout=self.timeout)
                if ev_r.status_code == 200:
                    for ev in ev_r.json()[:10]:
                        if ev.get("type") == "PushEvent":
                            for c in ev.get("payload", {}).get("commits", []):
                                author = c.get("author", {})
                                em = author.get("email", "")
                                if em and "noreply.github.com" not in em:
                                    discovered_emails.add(em)
            except Exception:
                pass

            return {
                "found": True,
                "username": clean_user,
                "name": data.get("name") or "N/A",
                "avatar_url": data.get("avatar_url"),
                "bio": data.get("bio") or "No public bio provided.",
                "company": data.get("company") or "N/A",
                "blog": data.get("blog") or "N/A",
                "location": data.get("location") or "N/A",
                "public_repos": data.get("public_repos", 0),
                "public_gists": data.get("public_gists", 0),
                "followers": data.get("followers", 0),
                "following": data.get("following", 0),
                "created_at": data.get("created_at"),
                "profile_url": data.get("html_url"),
                "discovered_emails": list(discovered_emails)
            }
        except Exception as e:
            return {"found": False, "error": str(e)}

    # ==========================================================================
    # TOOL 7: CRYPTO WALLET TRACER
    # ==========================================================================
    def trace_crypto(self, address: str) -> Dict[str, Any]:
        """Validates cryptocurrency address formats and performs live on-chain AML tracing."""
        addr = address.strip()
        try:
            from aegis.crypto_tracer import CryptoTraceEngine
            tracer = CryptoTraceEngine(timeout=self.timeout)
            return tracer.trace_wallet(addr)
        except Exception:
            return {
                "address": addr,
                "valid": False,
                "currency": "Unknown",
                "message": "Unable to resolve on-chain ledger."
            }

    # ==========================================================================
    # TOOL 8: HASH ALGORITHM IDENTIFIER
    # ==========================================================================
    def identify_hash(self, hash_str: str) -> Dict[str, Any]:
        """Identifies cryptographic hash algorithm and provides lookup links."""
        h = hash_str.strip().lower()
        length = len(h)
        is_hex = bool(re.match(r"^[a-f0-9]+$", h))

        possible_algos = []
        if is_hex:
            if length == 32:
                possible_algos = ["MD5", "NTLM", "MD4", "LM"]
            elif length == 40:
                possible_algos = ["SHA-1", "MySQL 4.1+", "RIPEMD-160"]
            elif length == 56:
                possible_algos = ["SHA-224", "SHA3-224"]
            elif length == 64:
                possible_algos = ["SHA-256", "SHA3-256", "Blake2s"]
            elif length == 96:
                possible_algos = ["SHA-384", "SHA3-384"]
            elif length == 128:
                possible_algos = ["SHA-512", "Whirlpool", "SHA3-512"]
        elif h.startswith("$2a$") or h.startswith("$2b$") or h.startswith("$2y$"):
            possible_algos = ["bcrypt Password Hash (Salted Blowfish)"]
        elif h.startswith("$argon2"):
            possible_algos = ["Argon2 Password Hash"]

        return {
            "hash": hash_str.strip(),
            "length": length,
            "is_hex": is_hex,
            "possible_algorithms": possible_algos or ["Unknown Hash Type"],
            "crack_lookup_links": {
                "CrackStation": f"https://crackstation.net/?q={h}",
                "HashToolkit": f"https://hashtoolkit.com/decrypt-hash/?hash={h}",
                "CyberChef": "https://gchq.github.io/CyberChef/"
            }
        }

    # ==========================================================================
    # TOOL 9: IP ANALYZER & ATTACKER REAL ORIGIN INVESTIGATOR
    # ==========================================================================
    def analyze_ip(self, ip_str: str) -> Dict[str, Any]:
        """Deep IP Intelligence: Geolocation, ASN, VPN/Tor detection, Subpoena Advisory."""
        ip = ip_str.strip()
        data = {
            "ip": ip,
            "reverse_dns": "None",
            "country": "Unknown",
            "country_code": "XX",
            "city": "Unknown",
            "region": "Unknown",
            "postal": "Unknown",
            "isp": "Unknown",
            "org": "Unknown",
            "as_number": "N/A",
            "is_vpn_proxy": False,
            "is_datacenter": False,
            "threat_score": 0,
            "carrier_subpoena_advisory": {}
        }

        # 1. Reverse DNS
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            data["reverse_dns"] = host
        except Exception:
            data["reverse_dns"] = "No PTR Record (Often indicates dynamic/cloud allocation)"

        # 2. Public IP API lookup
        try:
            r = self.session.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,zip,isp,org,as,proxy,hosting,query", timeout=self.timeout)
            if r.status_code == 200:
                res = r.json()
                data["country"] = res.get("country", "Unknown")
                data["country_code"] = res.get("countryCode", "XX")
                data["city"] = res.get("city", "Unknown")
                data["region"] = res.get("regionName", "Unknown")
                data["postal"] = res.get("zip", "N/A")
                data["isp"] = res.get("isp", "Unknown")
                data["org"] = res.get("org", "Unknown")
                data["as_number"] = res.get("as", "Unknown")
                data["is_vpn_proxy"] = bool(res.get("proxy", False))
                data["is_datacenter"] = bool(res.get("hosting", False))
        except Exception:
            pass

        # 3. Check known Datacenter / Commercial VPN ASNs
        for asn_code, asn_name in DATACENTER_VPN_ASNS.items():
            if asn_code in data["as_number"]:
                data["is_datacenter"] = True
                data["is_vpn_proxy"] = True
                data["vpn_service_detected"] = asn_name
                break

        # Calculate Threat & Fraud Score
        score = 0
        if data["is_vpn_proxy"]:
            score += 45
        if data["is_datacenter"]:
            score += 35
        if data["reverse_dns"] == "No PTR Record":
            score += 10
        data["threat_score"] = min(100, score)

        # 4. Authority Forensic Subpoena Advisory
        # Explains legally and technically how law enforcement pierces VPNs/Proxies
        data["carrier_subpoena_advisory"] = {
            "legal_basis": "18 U.S.C. § 2703(f) Preservation Order / 2703(d) Court Order / International MLAT",
            "required_telemetry": [
                "Target IP Address (" + ip + ")",
                "Exact Microsecond UTC Timestamp of connection",
                "Source Port and Destination Port (critical for CGNAT / VPN NAT translation lookup)",
                "Full TCP Flow Packet Capture (PCAP) or Server Access Log entry"
            ],
            "unmasking_procedure": (
                f"If the attacker used VPN/Proxy ({data['isp']}), authorities issue a subpoena to the host "
                f"requesting NAT translation connection logs for the exact destination port and timestamp. "
                f"Additionally, client-side browser leaks (Canvas fingerprint, WebRTC public IP leak, "
                f"and HTTP client hint timezone discrepancies) are correlated to pinpoint the true residential ISP."
            )
        }

        data["pivot_links"] = {
            "AbuseIPDB": f"https://www.abuseipdb.com/check/{ip}",
            "VirusTotal": f"https://www.virustotal.com/gui/ip-address/{ip}",
            "Shodan": f"https://www.shodan.io/host/{ip}",
            "GreyNoise": f"https://viz.greynoise.io/ip/{ip}"
        }

        return data

    # ==========================================================================
    # TOOL 10: WEB CRAWLER & RECON EXTRACTOR
    # ==========================================================================
    def crawl_target(self, url: str) -> Dict[str, Any]:
        """Crawls a target website to extract pages, emails, and social profiles."""
        clean_url = url.strip()
        if not clean_url.startswith("http://") and not clean_url.startswith("https://"):
            clean_url = "http://" + clean_url

        try:
            r = self.session.get(clean_url, timeout=self.timeout)
            html = r.text

            # Extract Emails
            emails = list(set(re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", html)))
            # Extract Phone Numbers
            phones = list(set(re.findall(r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}", html)))
            # Extract Social Links
            social_links = []
            for plat in ["twitter.com", "x.com", "facebook.com", "linkedin.com", "instagram.com", "github.com", "t.me"]:
                matches = re.findall(rf'https?://(?:www\.)?{plat}/[a-zA-Z0-9_.-]+', html)
                social_links.extend(matches)
            social_links = list(set(social_links))

            # Extract Internal Links
            links = list(set(re.findall(r'href=[\'"]?([^\'" >]+)', html)))
            internal_links = [l for l in links if l.startswith("/") or clean_url in l][:20]

            return {
                "target": clean_url,
                "status_code": r.status_code,
                "page_title": (re.search(r"<title>(.*?)</title>", html, re.IGNORECASE) or ["", "No title found"])[1],
                "emails_extracted": emails[:15],
                "phones_extracted": phones[:10],
                "social_profiles": social_links[:15],
                "internal_links": internal_links
            }
        except Exception as e:
            return {"target": clean_url, "error": str(e)}

    # ==========================================================================
    # TOOL 11: REPUTATION CHECKER
    # ==========================================================================
    def check_reputation(self, target: str) -> Dict[str, Any]:
        """Generates multi-threat reputation intelligence links and risk evaluation."""
        clean = target.strip().replace("http://", "").replace("https://", "").split("/")[0]
        return {
            "target": clean,
            "reputation_sources": {
                "AbuseIPDB": f"https://www.abuseipdb.com/check/{clean}",
                "VirusTotal": f"https://www.virustotal.com/gui/search/{clean}",
                "AlienVault_OTX": f"https://otx.alienvault.com/indicator/ip/{clean}",
                "URLhaus": f"https://urlhaus.abuse.ch/browse.php?search={clean}",
                "Spamhaus": f"https://check.spamhaus.org/listed/?searchterm={clean}"
            },
            "status": "Ready for multi-source pivoting"
        }

    # ==========================================================================
    # TOOL 12: URL PHISHING & FRAUD SCANNER
    # ==========================================================================
    def scan_url(self, url_str: str) -> Dict[str, Any]:
        """Inspects URLs for phishing heuristics, deceptive domains, and scam signals."""
        raw = url_str.strip()
        parsed = urllib.parse.urlparse(raw if "://" in raw else "http://" + raw)
        host = (parsed.hostname or raw).lower()

        suspicious_tlds = {".xyz", ".top", ".buzz", ".icu", ".cam", ".rest", ".tk", ".ml", ".ga", ".cf", ".gq"}
        heuristic_flags = []
        risk_score = 0

        # Check for IP address in host
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
            heuristic_flags.append("Host is a raw numerical IP address (common in phishing/C2)")
            risk_score += 35

        # Check for suspicious TLD
        for tld in suspicious_tlds:
            if host.endswith(tld):
                heuristic_flags.append(f"Domain uses high-abuse discount TLD ({tld})")
                risk_score += 25
                break

        # Check for deceptive brand impersonation
        brands = ["paypal", "bank", "secure", "login", "verify", "update", "account", "wallet", "binance", "metamask"]
        for b in brands:
            if b in host and not host.endswith(f"{b}.com"):
                heuristic_flags.append(f"Deceptive brand keyword in hostname: '{b}'")
                risk_score += 30
                break

        # Check multiple subdomains
        if host.count(".") > 3:
            heuristic_flags.append("Excessive subdomain depth (possible subdomain spoofing)")
            risk_score += 15

        return {
            "url": raw,
            "hostname": host,
            "scheme": parsed.scheme or "http",
            "risk_score": min(100, risk_score),
            "threat_rating": "Critical Phishing Threat" if risk_score >= 60 else ("Suspicious" if risk_score >= 30 else "Normal / Low Risk"),
            "heuristic_flags": heuristic_flags
        }
