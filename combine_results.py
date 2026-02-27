"""
combine_results.py

Combines outputs from all recon_ip subflows/tasks into a single
Elasticsearch-compatible JSON file. Each document in the output
array represents one host (IP) with all associated scan data.

Input files (provided via Kestra inputFiles):
    metadata.json      – scan context (execution_id, flow_id, etc.)
    nmap_output.json   – parsed nmap scan results
    websites.json      – httpx probe results grouped by host
    banner.json        – banner grabbing results
    asn.json           – ASN information
    waf.json           – WAF detection results
    cms.json           – CMS detection results
    nuclei.json        – Nuclei vulnerability scan results
    responses.json     – HTTP response headers/body

Output:
    combined_results.json – JSON array of Elasticsearch documents
"""

import json
import sys
from datetime import datetime, timezone


def safe_load_json(filepath, default=None):
    """Safely load a JSON file, returning *default* on any failure."""
    if default is None:
        default = []
    try:
        with open(filepath, "r") as fh:
            data = json.load(fh)
            if data is None:
                return default
            return data
    except (FileNotFoundError, json.JSONDecodeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Index builders – each function builds a lookup keyed by IP (or URL → IP)
# ---------------------------------------------------------------------------

def build_nmap_index(nmap_data):
    """Index nmap results by host IP."""
    index = {}
    if not isinstance(nmap_data, list):
        return index
    for entry in nmap_data:
        if not isinstance(entry, dict):
            continue
        ip = entry.get("host") or entry.get("ip") or entry.get("address")
        if not ip:
            continue
        index[ip] = entry
    return index


def build_websites_index(websites_data):
    """Index httpx/websites results by IP."""
    index = {}
    if not isinstance(websites_data, list):
        return index
    for entry in websites_data:
        if not isinstance(entry, dict):
            continue
        ip = entry.get("ip") or entry.get("host")
        if not ip:
            continue
        index[ip] = entry
    return index


def build_asn_index(asn_data):
    """Index ASN records by input IP."""
    index = {}
    if not isinstance(asn_data, list):
        return index
    for entry in asn_data:
        if not isinstance(entry, dict):
            continue
        ip = entry.get("input") or entry.get("ip")
        if not ip:
            continue
        index[ip] = entry
    return index


def build_banner_index(banner_data):
    """Index banner results by IP."""
    index = {}
    if not isinstance(banner_data, list):
        if isinstance(banner_data, dict):
            for ip, banners in banner_data.items():
                index[ip] = banners if isinstance(banners, list) else [banners]
            return index
        return index
    for entry in banner_data:
        if not isinstance(entry, dict):
            continue
        ip = entry.get("host") or entry.get("ip")
        if not ip:
            continue
        index.setdefault(ip, []).append(entry)
    return index


def extract_ip_from_url(url):
    """Best-effort extraction of host/IP from a URL string."""
    if not url:
        return None
    url = url.strip()
    # strip scheme
    for scheme in ("https://", "http://"):
        if url.startswith(scheme):
            url = url[len(scheme):]
            break
    # strip path/query
    url = url.split("/")[0]
    # strip port
    if ":" in url:
        url = url.rsplit(":", 1)[0]
    # strip brackets for IPv6
    url = url.strip("[]")
    return url if url else None


def build_waf_index(waf_data):
    """Index WAF results by IP extracted from URL."""
    index = {}
    if not isinstance(waf_data, list):
        return index
    for entry in waf_data:
        if not isinstance(entry, dict):
            continue
        ip = extract_ip_from_url(entry.get("url", ""))
        if not ip:
            continue
        index.setdefault(ip, []).append({
            "url": entry.get("url"),
            "detected": entry.get("detected", False),
            "firewall": entry.get("firewall"),
            "manufacturer": entry.get("manufacturer"),
        })
    return index


def build_cms_index(cms_data):
    """Index CMS results by IP extracted from URL."""
    index = {}
    if not isinstance(cms_data, list):
        return index
    for entry in cms_data:
        if not isinstance(entry, dict):
            continue
        url = entry.get("url") or entry.get("cms_url", "")
        ip = extract_ip_from_url(url)
        if not ip:
            continue
        index.setdefault(ip, []).append({
            "url": url,
            "name": entry.get("cms_name") or entry.get("name"),
            "id": entry.get("cms_id") or entry.get("id"),
            "version": entry.get("cms_version") or entry.get("version"),
        })
    return index


def build_nuclei_index(nuclei_data):
    """Index Nuclei findings by IP."""
    index = {}
    if not isinstance(nuclei_data, list):
        return index
    for entry in nuclei_data:
        if not isinstance(entry, dict):
            continue
        ip = entry.get("ip") or extract_ip_from_url(entry.get("host", ""))
        if not ip:
            continue
        info = entry.get("info", {}) or {}
        finding = {
            "template_id": entry.get("template-id") or entry.get("template_id"),
            "name": info.get("name"),
            "severity": info.get("severity"),
            "description": info.get("description"),
            "tags": info.get("tags", []),
            "type": entry.get("type"),
            "matched_at": entry.get("matched-at") or entry.get("matched_at"),
        }
        index.setdefault(ip, []).append(finding)
    return index


def build_responses_index(responses_data):
    """Index HTTP response data by IP."""
    index = {}
    if isinstance(responses_data, list):
        for entry in responses_data:
            if not isinstance(entry, dict):
                continue
            ip = extract_ip_from_url(entry.get("url", ""))
            if ip:
                index.setdefault(ip, []).append(entry)
    elif isinstance(responses_data, dict):
        for url, resp in responses_data.items():
            ip = extract_ip_from_url(url)
            if ip:
                index.setdefault(ip, []).append(resp)
    return index


# ---------------------------------------------------------------------------
# Document builder
# ---------------------------------------------------------------------------

def build_port_entries(nmap_entry):
    """Extract port/service info from an nmap entry."""
    ports = nmap_entry.get("ports", [])
    if not isinstance(ports, list):
        return []
    result = []
    for p in ports:
        if not isinstance(p, dict):
            continue
        svc = p.get("service", {}) or {}
        result.append({
            "port": p.get("port") or p.get("portid"),
            "protocol": p.get("protocol", "tcp"),
            "state": p.get("state"),
            "service": {
                "name": svc.get("name"),
                "product": svc.get("product"),
                "version": svc.get("version"),
                "extra_info": svc.get("extrainfo"),
                "os_type": svc.get("ostype"),
            },
        })
    return result


def build_service_entries(websites_entry):
    """Extract web service details from httpx/websites entry."""
    services = websites_entry.get("services", [])
    if not isinstance(services, list):
        return []
    result = []
    for svc in services:
        if not isinstance(svc, dict):
            continue
        entry = {
            "port": svc.get("port"),
            "url": svc.get("url"),
            "status_code": svc.get("status"),
            "title": svc.get("title"),
            "server": svc.get("server"),
            "content_type": svc.get("content_type"),
            "response_time": svc.get("response_time"),
            "technologies": svc.get("technologies", []),
            "redirect": svc.get("redirect"),
            "jarm": svc.get("jarm"),
            "cdn": svc.get("cdn"),
        }
        tls = svc.get("tls")
        if tls and isinstance(tls, dict):
            entry["tls"] = {
                "version": tls.get("version"),
                "cipher": tls.get("cipher"),
                "subject_cn": tls.get("subject_cn"),
                "subject_org": tls.get("subject_org"),
                "issuer": tls.get("issuer"),
                "not_before": tls.get("valid_from") or tls.get("not_before"),
                "not_after": tls.get("valid_to") or tls.get("not_after"),
                "fingerprint": tls.get("fingerprints") or tls.get("fingerprint"),
            }
        result.append(entry)
    return result


def build_asn_entry(asn_record):
    """Normalise a single ASN record."""
    if not asn_record or not isinstance(asn_record, dict):
        return None
    return {
        "number": asn_record.get("as_number") or asn_record.get("asn"),
        "name": asn_record.get("as_name") or asn_record.get("name"),
        "country": asn_record.get("as_country") or asn_record.get("country"),
        "range": asn_record.get("as_range") or asn_record.get("range"),
    }


def build_host_document(ip, metadata, indices):
    """Build a single Elasticsearch document for one IP host."""
    nmap_idx, web_idx, asn_idx, banner_idx = (
        indices["nmap"],
        indices["websites"],
        indices["asn"],
        indices["banner"],
    )
    waf_idx, cms_idx, nuclei_idx, resp_idx = (
        indices["waf"],
        indices["cms"],
        indices["nuclei"],
        indices["responses"],
    )

    doc = {
        "@timestamp": metadata.get("start_date") or datetime.now(timezone.utc).isoformat(),
        "event": {
            "kind": "asset",
            "category": ["host", "network"],
            "module": "easm_recon",
        },
        "scan": {
            "execution_id": metadata.get("execution_id"),
            "flow_id": metadata.get("flow_id", "recon_ip"),
            "namespace": metadata.get("namespace", "easm"),
            "target": metadata.get("input_target"),
            "region": metadata.get("region"),
        },
        "host": {
            "ip": ip,
        },
    }

    # -- Ports from nmap -----------------------------------------------
    nmap_entry = nmap_idx.get(ip, {})
    port_entries = build_port_entries(nmap_entry) if nmap_entry else []
    if port_entries:
        doc["network"] = {"ports": port_entries}

    os_info = nmap_entry.get("os") if nmap_entry else None
    if os_info:
        doc["host"]["os"] = os_info

    # -- Web services from httpx ----------------------------------------
    web_entry = web_idx.get(ip, {})
    service_entries = build_service_entries(web_entry) if web_entry else []
    if service_entries:
        doc["services"] = service_entries

    # -- ASN ------------------------------------------------------------
    asn_entry = build_asn_entry(asn_idx.get(ip))
    if asn_entry:
        doc["asn"] = asn_entry

    # -- Banner ---------------------------------------------------------
    banners = banner_idx.get(ip, [])
    if banners:
        doc["banner"] = banners

    # -- WAF ------------------------------------------------------------
    waf_entries = waf_idx.get(ip, [])
    if waf_entries:
        doc["waf"] = waf_entries

    # -- CMS ------------------------------------------------------------
    cms_entries = cms_idx.get(ip, [])
    if cms_entries:
        doc["cms"] = cms_entries

    # -- Vulnerabilities (Nuclei) ---------------------------------------
    vuln_entries = nuclei_idx.get(ip, [])
    if vuln_entries:
        doc["vulnerabilities"] = vuln_entries

    # -- OpenVAS --------------------------------------------------------
    openvas_id = metadata.get("openvas_report_id")
    if openvas_id:
        doc["openvas"] = {"report_id": openvas_id}

    # -- Responses ------------------------------------------------------
    resp_entries = resp_idx.get(ip, [])
    if resp_entries:
        doc["responses"] = resp_entries

    return doc


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    # Load all input files
    metadata = safe_load_json("metadata.json", {})
    nmap_data = safe_load_json("nmap_output.json")
    websites_data = safe_load_json("websites.json")
    banner_data = safe_load_json("banner.json")
    asn_data = safe_load_json("asn.json")
    waf_data = safe_load_json("waf.json")
    cms_data = safe_load_json("cms.json")
    nuclei_data = safe_load_json("nuclei.json")
    responses_data = safe_load_json("responses.json", {})

    # Build lookup indices keyed by IP
    indices = {
        "nmap": build_nmap_index(nmap_data),
        "websites": build_websites_index(websites_data),
        "asn": build_asn_index(asn_data),
        "banner": build_banner_index(banner_data),
        "waf": build_waf_index(waf_data),
        "cms": build_cms_index(cms_data),
        "nuclei": build_nuclei_index(nuclei_data),
        "responses": build_responses_index(responses_data),
    }

    # Collect all unique IPs from every data source
    all_ips = set()
    for idx in indices.values():
        all_ips.update(idx.keys())

    # Build one Elasticsearch document per host
    documents = []
    for ip in sorted(all_ips):
        doc = build_host_document(ip, metadata, indices)
        documents.append(doc)

    # If no hosts were found across any source, produce an empty array
    if not documents:
        print("Warning: no host data found in any input file", file=sys.stderr)

    with open("combined_results.json", "w") as out:
        json.dump(documents, out, indent=2, default=str)

    print(f"Combined {len(documents)} host document(s) into combined_results.json")


if __name__ == "__main__":
    main()
