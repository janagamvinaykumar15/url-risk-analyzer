import sys
import urllib.parse

# Define high-risk extensions and keywords
RISK_EXTENSIONS = (
    '.env', '.bak', '.old', '.sql', '.db',
    '.zip', '.map', '.yml', '.yaml', '.json'
)

RISK_KEYWORDS = [
    'admin', 'api-docs', 'swagger', '.git',
    'actuator', 'phpinfo', 'secret', 'token', 'config'
]


def analyze_urls(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip()]

    high_risk = []

    for url in urls:
        parsed = urllib.parse.urlparse(url)
        path = parsed.path.lower()
        query = parsed.query.lower()

        # Check 1: File Extensions
        if path.endswith(RISK_EXTENSIONS):
            high_risk.append((url, "High-risk file extension"))
            continue

        # Check 2: Path Keywords
        for kw in RISK_KEYWORDS:
            if kw in path:
                high_risk.append(
                    (url, f"path contains keyword: '{kw}'")
                )
                break

        # Check 3: Query Parameter Secrets
        if query:
            params = urllib.parse.parse_qs(query)

            for param in params:
                for kw in ['key', 'secret', 'token', 'auth', 'pass', 'signature']:
                    if kw in param.lower():
                        high_risk.append(
                            (url, f"Parameter contains sensitive keyword: '{param}'")
                        )
                        break

    # Output Results
    print(
        f"[*] Analysis complete. Found {len(high_risk)} "
        f"high-risk URLs out of {len(urls)} total."
    )

    for url, reason in high_risk:
        print(f"\n[!] Reason: {reason}\n   URL: {url}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python analyze.py <path_to_url_list.txt>")
    else:
        analyze_urls(sys.argv[1])
