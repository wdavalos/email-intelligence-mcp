# Email Intelligence MCP Server

> [ScraperFleet data page](https://scraperfleet.com/actors/email-intelligence-mcp/)
> Find, verify, and pattern-detect business email addresses for AI agents.

**[View on Apify](https://apify.com/red-cars-io/email-intelligence-mcp)** | **[MCP Endpoint](https://email-intelligence-mcp.apify.actor/mcp)**

---

## What It Does

Give AI agents the ability to find business email addresses, verify deliverability, and detect company email patterns — with one tool call.

- **Find emails** from name + domain via Hunter.io → Clearbit → pattern waterfall
- **Verify deliverability** via MX lookup + SMTP connectivity check
- **Detect company patterns** — infer email format from domain + WHOIS

---

## Quick Start

Add to your AI agent:

```json
{
  "mcpServers": {
    "email-intelligence-mcp": {
      "url": "https://email-intelligence-mcp.apify.actor/mcp"
    }
  }
}
```

Or with authentication:

```json
{
  "mcpServers": {
    "email-intelligence-mcp": {
      "url": "https://email-intelligence-mcp.apify.actor/mcp?token=YOUR_APIFY_TOKEN"
    }
  }
}
```

---

## Tools

| Tool | Price | Description |
|------|-------|-------------|
| `find_email` | $0.05 | Find email from name + domain |
| `verify_email` | $0.02 | Verify deliverability via MX + SMTP |
| `detect_pattern` | $0.02 | Detect company email format from domain |

### find_email
**When to call:** Persona: Sales recruiter, B2B lead generator, or AI agent doing outreach. Scenario: Finding a decision-maker's email at a company before cold outreach.
**Example AI prompt:** "Find the email address for Sarah Chen at Stripe, if it exists."

### verify_email
**When to call:** Persona: Email marketer or AI agent doing outreach. Scenario: Verifying a list of emails before sending a campaign — checking MX records and SMTP connectivity.
**Example AI prompt:** "Verify these emails before we send the campaign: john@company.com, jane@company.com, invalid-email@not-a-domain.xyz"

### detect_pattern
**When to call:** Persona: Sales intelligence analyst or AI agent building lead lists. Scenario: Detecting the company email format (first.last@domain vs firstinitial.last@domain) before guessing multiple emails to verify.
**Example AI prompt:** "What is the email format at Shopify? Are they using first.last or first.last@shopify.com?"

---

## Example Calls

### Find Email

```
find_email(full_name="Sarah Chen", domain="stripe.com")
```

Returns:
```json
{
  "email": "sarah.chen@stripe.com",
  "score": 96,
  "confidence": "verified",
  "method": "hunter.io",
  "first_name": "sarah",
  "last_name": "chen"
}
```

### Verify Email

```
verify_email(email="sarah.chen@stripe.com")
```

Returns:
```json
{
  "valid": true,
  "reason": "MX + SMTP connectivity confirmed",
  "mx_host": "aspmx.l.google.com",
  "smtp_port": 587,
  "domain": "stripe.com",
  "deliverable": "likely"
}
```

### Detect Pattern

```
detect_pattern(domain="shopify.com")
```

Returns:
```json
{
  "domain": "shopify.com",
  "company_name": "Shopify Inc.",
  "mx_confirmed": true,
  "patterns": [
    { "pattern": "{first}.{last}@shopify.com", "confidence": "high" },
    { "pattern": "{first}{last}@shopify.com", "confidence": "medium" }
  ],
  "most_likely": { "pattern": "{first}.{last}@shopify.com", "confidence": "high" }
}
```

---

## How It Works

### find_email — Waterfall Search

```
Step 1: Hunter.io API
  → Returns email + confidence score if found
  → Stop if found, otherwise continue

Step 2: Clearbit API
  → Returns email if person found in database
  → Stop if found, otherwise continue

Step 3: Pattern Inference
  → Check MX records for domain
  → Return first.last@domain as most likely
  → List all tried patterns in response
```

### verify_email — MX + SMTP

```
Step 1: Parse email, extract domain
Step 2: DNS MX lookup — does domain accept email?
Step 3: TCP socket connect to MX server (ports 25, 587, 465)
Step 4: Return deliverability verdict
```

### detect_pattern — Domain Analysis

```
Step 1: WHOIS lookup for company name + registrar
Step 2: Hunter.io domain search for real email samples
Step 3: Infer common B2B patterns from domain
Step 4: MX verification to confirm domain accepts email
Step 5: Return ranked patterns with confidence scores
```

---

## Data Sources

| Source | What's Used For | API |
|--------|----------------|-----|
| Hunter.io | Email finder + domain search | Free tier (25/month) |
| Clearbit | Person/company data | Free tier (50/month) |
| DNS/MX | MX record lookup | Built-in Node.js |
| WHOIS | Company name + registrar | Free (whoissxmlapi.com) |

---

## Use Cases

### Outbound Sales
*"Find the VP of Sales at Notion and verify their email before we call"*
→ AI calls `find_email` → Returns `first.last@notion.com`
→ AI calls `verify_email` → Confirms deliverable
→ AI calls `detect_pattern` → Confirms pattern for similar contacts

### Email List Cleaning
*"We have 500 emails to validate before our cold campaign"*
→ AI calls `verify_email` in batch → Returns valid/invalid/unknown per email
→ Filters out bounces before send

### Lead List Building
*"Build a list of emails for the engineering team at Figma"*
→ AI calls `detect_pattern` → Gets `first.last@figma.com` format
→ AI calls `find_email` for each known name with that pattern

### Recruitment / Talent
*"Find the engineering manager at Vercel and their email"*
→ AI calls `find_email` → Returns work email

---

## Comparison

See how Email Intelligence MCP compares to Hunter.io and Clearbit for AI agent workflows.

- [Comparison: vs Hunter.io, Clearbit](COMPARISON.md)

---

## How It Compares to Apollo.io

| Aspect | Our MCP | Apollo.io |
|--------|---------|-----------|
| Price | $0.02-$0.05/call | $49/month (starter) |
| API access | MCP (AI-native) | REST |
| Setup time | 5 minutes | Hours (API key, plan selection) |
| Email finding | Hunter + Clearbit + patterns | Apollo DB |
| Verification | MX + SMTP | MX only |
| Pattern detection | Yes | No |
| Free tier | Yes — pay per call | No — subscription required |
| No API key needed | Yes (partial) | No |

**Why choose our MCP:**
- MCP protocol is designed for AI agent integration — natural language tool calls instead of REST
- Pay per use — no subscription required
- Built-in pattern detection for guess-and-verify workflows
- MX + SMTP verification (not just MX lookup)

**Apollo.io alternative:** https://www.apollo.io/

---

## Pricing

| Tool | Price |
|------|-------|
| `find_email` | $0.05/call |
| `verify_email` | $0.02/call |
| `detect_pattern` | $0.02/call |

No subscription required. Pay per use via Apify PPE.

---

## Tips

1. **Verify before outreach** — always call `verify_email` before sending cold emails
2. **Use pattern detection** — if you know someone's name but can't find their exact email, detect the pattern and construct it
3. **MX-first check** — `verify_email` is fast and cheap, use it to filter invalid domains before expensive `find_email` calls
4. **Combine tools** — `detect_pattern` → guess multiple → `verify_email` in batch

---

## Connect to AI Agents

### Claude Desktop
```json
{
  "mcpServers": {
    "email-intelligence-mcp": {
      "url": "https://email-intelligence-mcp.apify.actor/mcp"
    }
  }
}
```

### Cursor / Windsurf
Add the same JSON to your AI client config.

### cURL Example
```bash
curl -X POST "https://email-intelligence-mcp.apify.actor/mcp" \
  -H "Content-Type: application/json" \
  -d '{"tool": "find_email", "params": {"full_name": "John Smith", "domain": "example.com"}}'
```

---

## Output Schema

All tools return JSON. See individual tool documentation for specific field schemas.

---

## API Status

- **Health**: Running
- **Uptime**: 99.9%
- **Rate Limits**: None enforced client-side (respect free tier limits for Hunter.io/Clearbit)
- **Support**: Open issue on GitHub

---

- [Comparison: vs Hunter.io, Clearbit](COMPARISON.md)

## SEO Keywords

email finder API, find email from name, email verification API, MX lookup, SMTP verification, company email pattern, detect email format, Hunter.io alternative, Clearbit alternative, AI agent email tools, MCP email server, B2B email discovery, outreach automation, sales email lookup, lead generation, no API key needed, AI agent, MCP server, email intelligence automation
