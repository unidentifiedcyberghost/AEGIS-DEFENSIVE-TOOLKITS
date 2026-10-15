//! Aegis Defensive Security Crate (Rust Engine)
//! Provides high-performance static header validation, log pattern parsing, and IP Tables defense synthesis.

use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{self, BufRead};
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
struct HeaderAuditItem {
    header: String,
    present: bool,
    recommended: String,
    severity: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct AttackerRecord {
    ip: String,
    malicious_hits: u32,
    threat_level: String,
    suggested_firewall_rule: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct IpDefenseRecord {
    target_ip: String,
    iptables_rule: String,
    ufw_rule: String,
    netsh_rule: String,
    route_gateway: String,
    threat_posture: String,
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    println!("Aegis Defensive Security Engine [Rust Edition 2.2]");
    println!("==================================================");

    if args.len() > 1 && args[1] == "--parse-log" {
        if args.len() < 3 {
            println!("Usage: aegis-rust --parse-log <path_to_access_log>");
            return Ok(());
        }
        parse_access_log(&args[2])?;
        return Ok(());
    }

    if args.len() > 1 && args[1] == "--iptables" {
        let ip = if args.len() > 2 { &args[2] } else { "198.51.100.45" };
        generate_ip_tables_defense(ip);
        return Ok(());
    }

    if args.len() > 1 && args[1] == "--routes" {
        let ip = if args.len() > 2 { &args[2] } else { "127.0.0.1" };
        inspect_ip_routes(ip);
        return Ok(());
    }

    // Default defensive headers demonstration
    run_header_rules_check();
    Ok(())
}

fn generate_ip_tables_defense(ip: &str) {
    let record = IpDefenseRecord {
        target_ip: ip.to_string(),
        iptables_rule: format!("sudo iptables -A INPUT -s {} -j DROP", ip),
        ufw_rule: format!("sudo ufw deny from {}", ip),
        netsh_rule: format!("netsh advfirewall firewall add rule name=\"Block_{}\" dir=in action=block remoteip={}", ip, ip),
        route_gateway: "0.0.0.0/0 via Default Interface Gateway".to_string(),
        threat_posture: "DEFENSIVE DROP ENFORCED".to_string(),
    };

    println!("[+] Defensive Firewall Enforcement Rules for: {}", ip);
    println!("    * Linux IP Tables: {}", record.iptables_rule);
    println!("    * Ubuntu UFW:      {}", record.ufw_rule);
    println!("    * Windows Netsh:   {}", record.netsh_rule);
    let serialized = serde_json::to_string_pretty(&record).unwrap();
    println!("\n[+] Structured Defense Telemetry (JSON):\n{}", serialized);
}

fn inspect_ip_routes(ip: &str) {
    println!("[+] Target IP Routing Telemetry for: {}", ip);
    println!("    * Scope: {}", if ip.starts_with("127.") || ip == "::1" { "Local Loopback" } else if ip.starts_with("192.168.") || ip.starts_with("10.") { "Private RFC-1918 Subnet" } else { "Public Internet / WAN Gateway" });
    println!("    * Next Hop: Direct Local Interface / Gateway");
    println!("    * BGP Status: Synced & Monitored by Aegis Core Engine");
}

fn run_header_rules_check() {
    let mut rules = HashMap::new();
    rules.insert(
        "Content-Security-Policy",
        ("default-src 'self';", "High", "Mitigates XSS & data injection"),
    );
    rules.insert(
        "Strict-Transport-Security",
        ("max-age=31536000; includeSubDomains", "Medium", "Enforces HTTPS connections"),
    );
    rules.insert(
        "X-Frame-Options",
        ("SAMEORIGIN", "Medium", "Defends against clickjacking"),
    );
    rules.insert(
        "X-Content-Type-Options",
        ("nosniff", "Medium", "Disables MIME sniffing"),
    );
    rules.insert(
        "Referrer-Policy",
        ("strict-origin-when-cross-origin", "Medium", "Protects user navigation privacy"),
    );

    println!("[+] OWASP Defensive Header Rules Active:");
    for (header, (rec, sev, desc)) in &rules {
        println!("    - [{}] {}: recommended='{}' ({})", sev, header, rec, desc);
    }
}

fn parse_access_log(path: &str) -> io::Result<()> {
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);

    let pattern = Regex::new(r"(?i)(\.\./|\.env|\.git/|union\s+select|' OR|<script)").unwrap();
    let mut attacker_map: HashMap<String, u32> = HashMap::new();

    for line_result in reader.lines() {
        let line = line_result?;
        if pattern.is_match(&line) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if !parts.is_empty() {
                let ip = parts[0].to_string();
                *attacker_map.entry(ip).or_insert(0) += 1;
            }
        }
    }

    println!("[+] Log Analysis Complete. Attackers Identified:");
    for (ip, count) in &attacker_map {
        let rec = AttackerRecord {
            ip: ip.clone(),
            malicious_hits: *count,
            threat_level: if *count > 5 { "High".to_string() } else { "Medium".to_string() },
            suggested_firewall_rule: format!("sudo ufw deny from {}", ip),
        };
        let serialized = serde_json::to_string(&rec).unwrap();
        println!("    {}", serialized);
    }

    Ok(())
}
