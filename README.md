 SSO Protocol Scanner

An automated web application scanner that identifies and classifies Single Sign-On (SSO) authentication protocols and flows. Built to streamline security audits, SSO migrations, and application inventory management.

![Python](https://img.shields.io/badge/python-3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Playwright](https://img.shields.io/badge/playwright-latest-orange.svg)

Table of Contents

- [Problem Statement](#-problem-statement)
- [Solution](#-solution)
- [Supported Protocols](#-supported-protocols)
- [Features](#-features)
- [Installation](#-installation)
- Ethics and usage

 Problem Statement

When managing enterprise applications, security professionals and IT administrators face several challenges:

- **Manual Inspection**: Identifying which OAuth flow each target app uses requires opening browser DevTools, triggering login, and analyzing network traffic manually
- **Time-Consuming**: Auditing dozens or hundreds of applications takes hours or days
- **Inconsistent Documentation**: Different team members document findings differently
- **Error-Prone**: Manual inspection leads to missed protocols or misclassification
- **Scale Issues**: No efficient way to inventory SSO implementations across large application portfolios

##  Solution

SSO Protocol Scanner automates the entire authentication detection workflow:

1. **Automated Browsing**: Visits each target URL using Playwright browser automation
2. **Network Monitoring**: Captures and analyzes all authentication-related HTTP requests
3. **Intelligent Detection**: Automatically finds and clicks SSO/login buttons using multiple heuristics
4. **Protocol Classification**: Identifies OAuth 2.0, OIDC, SAML 2.0, and WS-Federation protocols
5. **Flow Analysis**: Determines specific OAuth flows (Authorization Code, Implicit, Hybrid)
6. **Parameter Extraction**: Captures detailed authentication parameters (client_id, response_type, tenant info)
7. **Structured Reporting**: Generates comprehensive CSV reports for further analysis

**Result**: What took hours now completes in minutes with consistent, reliable results.

##  Supported Protocols

| Protocol | Detection Method | Key Details Extracted |
|----------|------------------|----------------------|
| **OAuth 2.0** | `/authorize` endpoint detection | client_id, response_type, response_mode, redirect_uri, code_challenge_method |
| **OpenID Connect (OIDC)** | `openid` scope or `id_token` in response | All OAuth details + OIDC flag, tenant host, x-client-SKU/VER |
| **SAML 2.0** | SAMLRequest/SAMLResponse detection | Binding type (POST/Redirect), RelayState, IdP host, flow direction |
| **WS-Federation** | WS-Fed specific parameters | wa, wtrealm, wreply, wctx, IdP host |

## 🚀 Features

✅ **Concurrent Scanning**: Process multiple URLs in parallel (configurable concurrency)  
✅ **Auto-Login Detection**: Intelligently finds and clicks login buttons ("Sign in", "SSO", "Continue")  
✅ **Flow Classification**: Categorizes OAuth flows into Authorization Code, Implicit, or Hybrid  
✅ **PKCE Detection**: Identifies if Authorization Code Flow uses PKCE (code_challenge_method)  
✅ **Multi-Protocol**: Detects OAuth/OIDC, SAML 2.0, and WS-Federation in a single scan  
✅ **Detailed Reporting**: Generates two CSV files - auth detected vs. no auth detected  
✅ **Debug Mode**: Run with visible browser (`--headed`) for troubleshooting  
✅ **Comprehensive Logging**: Captures status, notes, and diagnostic information  

## 💻 Installation

### Prerequisites

- Python 3.7 or higher
- pip (Python package manager)

### Setup Steps

```bash
# Clone the repository
git clone https://github.com/gurudeepmallam-cmd/SSO-Protocol-Scanner.git
cd SSO-Protocol-Scanner

# Install Python dependencies
pip install playwright

# Install Playwright browser (Chromium)
playwright install chromium

Verify Installation
Bashpython scanner.py --help

You should see the help menu with all available options.
🎯 Usage
Basic Usage
Bash# Step 1: Create input file with URLs (one per line)
echo "https://portal.example.com" > url.txt
echo "https://app.example.com" >> url.txt
echo "https://dashboard.example.com" >> url.txt

# Step 2: Run the scanner
python scanner.py --in url.txt --out results.csv

# Step 3: Review outputs
# - results_auth.csv (apps with detected protocols)
# - results_auth_no_auth.csv (apps without detected protocols)

Advanced Usage
Bash# Custom concurrency and timeout
python scanner.py \
  --in url.txt \
  --out auth_results.csv \
  --out-noauth noauth_results.csv \
  --concurrency 10 \
  --timeout-ms 20000

# Debug mode with visible browser
python scanner.py \
  --in url.txt \
  --out results.csv \
  --headed

Command-Line Parameters



Parameter
Default
Description




--in
url.txt
Input file containing URLs (one per line)


--out
output.csv
Output CSV for apps with detected authentication


--out-noauth
*_no_auth.csv
Output CSV for apps without detected authentication


--concurrency
5
Number of parallel browser instances


--timeout-ms
15000
Timeout per URL in milliseconds


--headed
False
Run with visible browser (for debugging)



Input File Format
Create a text file with one URL per line:
Unknownhttps://portal.contoso.com
https://app.fabrikam.com
dashboard.example.com
www.myapp.org

Note: URLs without http:// or https:// will automatically get https:// prepended.
📊 Output Format
The scanner generates two CSV files for easy analysis:
1. Authentication Detected (*_auth.csv)
Contains all applications where OAuth/OIDC, SAML, or WS-Fed was successfully detected:
Key Columns:

input_url: Original URL scanned
status: authorize_seen, saml_seen, or wsfed_seen
protocol: oauth2, oidc, saml2, or wsfed
protocol_flow: Specific flow type
flow: OAuth flow classification (auth_code, implicit, hybrid_or_mixed)
response_type: OAuth response_type parameter
client_id: OAuth client identifier
tenant_host: Identity provider hostname
is_oidc: true if OpenID Connect detected
saml_binding: POST or Redirect (for SAML)
auto_click_used: true if login button was auto-clicked

Example:
Unknowninput_url,status,protocol,protocol_flow,flow,response_type,client_id,tenant_host,is_oidc
https://app.example.com,authorize_seen,oidc,auth_code,auth_code,code,abc-123-xyz,login.microsoftonline.com,true
https://portal.example.com,saml_seen,saml2,saml_sp_initiated_request,saml_unknown,,,,false

2. No Authentication Detected (*_no_auth.csv)
Contains applications where no authentication protocol was detected:
Key Columns:

input_url: Original URL scanned
status: no_auth_seen, no_auth_seen_after_click, timeout_loading, error_loading
auto_click_used: true if click was attempted
notes: Diagnostic information explaining why auth wasn't detected

Example:
Unknowninput_url,status,auto_click_used,notes
https://static.example.com,no_auth_seen,false,"No OAuth/SAML/WS-Fed request observed; login UI not found/clickable."
https://timeout.example.com,timeout_loading,false,"Timed out loading page."

🔧 How It Works
Architecture Overview
UnknownInput URLs (url.txt)
       ↓
URL Normalization
       ↓
Concurrent Browser Instances (Playwright)
       ↓
Network Request Monitoring
       ↓
Pattern Matching & Protocol Detection
       ↓
Auto-Click Login UI (if needed)
       ↓
Parameter Extraction & Classification
       ↓
CSV Report Generation

Detailed Workflow


Input Processing

Reads URLs from input file
Normalizes URLs (adds https:// if missing)



Browser Automation

Launches Chromium browsers via Playwright
Creates isolated browser contexts per URL
Configurable concurrency with semaphore control



Network Monitoring

Attaches request listeners to capture all HTTP requests
Monitors both main page and iframe requests
Captures POST data for SAML detection



Protocol Detection (uses multiple heuristics)

OAuth/OIDC: Looks for /authorize endpoint with client_id, response_type parameters
SAML: Detects SAMLRequest/SAMLResponse in URL query or POST body
WS-Fed: Identifies wa=wsignin and related WS-Federation parameters



Intelligent Login Triggering

Searches page content for login-related keywords: "Sign in", "SSO", "Continue to SSO", etc.
Uses multiple selector strategies (role, text, button, link)
Checks both main page and iframes
Attempts scroll-into-view and force-click if needed



Flow Classification

Authorization Code: response_type=code
Implicit: response_type=token or id_token
Hybrid: Mixed response types (e.g., code id_token, code token)



Parameter Extraction

Parses query parameters from authentication URLs
Extracts tenant information, client IDs, scopes, PKCE methods
Captures SAML binding types and RelayState
Records WS-Fed parameters (wtrealm, wreply, wctx)



Report Generation

Splits results into auth-detected and no-auth files
Outputs structured CSV with comprehensive column set
Includes diagnostic notes for troubleshooting

##Ethics and usage


Responsible Use

✅ Use only on applications you own or have explicit permission to test
✅ Respect robots.txt and rate limiting policies
✅ Be mindful of production environments during business hours
✅ Do not use for unauthorized access attempts or penetration testing without authorization
✅ Follow your organization's security and compliance policies

Data Privacy

The scanner captures authentication metadata (URLs, protocol details) but does not capture credentials
No passwords, tokens, or sensitive data are logged
Review CSV outputs before sharing to ensure no sensitive information is included
