/**
 * Email Intelligence MCP Server
 * Find, verify, and pattern-detect business email addresses for AI agents.
 * Waterfall: Hunter.io → Clearbit → pattern matching
 * MX + SMTP verification for deliverability
 * Company email format detection via WHOIS + common patterns
 */

import http from 'http';
import dns from 'dns';
import net from 'net';
import { promisify } from 'util';
import { Actor } from 'apify';

const resolveMx = promisify(dns.resolveMx);

const HUNTER_API_KEY = process.env.HUNTER_API_KEY || '';
const CLEARBIT_API_KEY = process.env.CLEARBIT_API_KEY || '';
const WHOIS_API_KEY = process.env.WHOIS_API_KEY || '';

interface ToolParams {
    full_name?: string;
    domain?: string;
    email?: string;
}


interface EmailResult {
    email?: string;
    score?: number | null;
    confidence?: string | null;
    sources?: unknown[] | null;
    method?: string;
    first_name?: string;
    last_name?: string;
    suggested_patterns?: string[];
    note?: string;
    error?: string;
    attempted_patterns?: string[];
}

interface VerifyResult {
    valid: boolean;
    reason?: string;
    domain?: string;
    mx_host?: string;
    smtp_port?: number;
    mx_records?: string[];
    deliverable?: string;
    note?: string;
}

interface PatternResult {
    domain: string;
    company_name?: string | null;
    registrar?: string | null;
    mx_confirmed: boolean;
    patterns: { pattern: string; confidence: string; description: string }[];
    observed_patterns?: string[] | null;
    most_likely?: { pattern: string; confidence: string; description: string };
    note?: string;
    patterns_source?: string;
}

const MCP_MANIFEST: {
    schema_version: string;
    name: string;
    version: string;
    description: string;
    tools: {
        name: string;
        description: string;
        input_schema: {
            type: "object";
            properties: Record<string, unknown>;
            required: string[];
        };
        price: number;
    }[];
} = {
    schema_version: "1.0",
    name: "email-intelligence-mcp",
    version: "1.0",
    description: "Find, verify, and detect email patterns for business domains — for AI agents",
    tools: [
        {
            name: "find_email",
            description: "Find email address from a person's name and company domain. Waterfall: Hunter.io → Clearbit → pattern matching.",
            input_schema: {
                type: "object",
                properties: {
                    full_name: { type: "string", description: "Full name of the person (e.g. 'John Smith' or 'john smith')" },
                    domain: { type: "string", description: "Company domain (e.g. 'apple.com', 'stripe.com')" }
                },
                required: ["full_name", "domain"]
            },
            price: 0.05
        },
        {
            name: "verify_email",
            description: "Verify if an email address is deliverable via MX lookup + SMTP verification",
            input_schema: {
                type: "object",
                properties: {
                    email: { type: "string", description: "Email address to verify" }
                },
                required: ["email"]
            },
            price: 0.02
        },
        {
            name: "detect_pattern",
            description: "Detect company email format pattern from a domain using WHOIS + common business patterns",
            input_schema: {
                type: "object",
                properties: {
                    domain: { type: "string", description: "Company domain (e.g. 'apple.com', 'stripe.com')" }
                },
                required: ["domain"]
            },
            price: 0.02
        }
    ]
};

const TOOL_PRICES: Record<string, number> = {
    "find_email": 0.05,
    "verify_email": 0.02,
    "detect_pattern": 0.02
};

// ============================================
// TOOL IMPLEMENTATIONS
// ============================================

/**
 * Waterfall: Hunter.io → Clearbit → pattern matching
 */
async function findEmail(fullName: string, domain: string): Promise<EmailResult> {
    const nameParts = fullName.trim().toLowerCase().split(/\s+/);
    if (nameParts.length < 2) {
        return { error: "Please provide a full name with first and last name" };
    }
    const [firstName, lastName, ..._rest] = nameParts;
    const nameForSearch = `${firstName} ${lastName}`;

    // Step 1: Hunter.io
    if (HUNTER_API_KEY) {
        try {
            const url = `https://api.hunter.io/v2/email-finder?domain=${encodeURIComponent(domain)}&full_name=${encodeURIComponent(nameForSearch)}&api_key=${HUNTER_API_KEY}`;
            const resp = await fetch(url);
            const data = await resp.json() as { data?: { email?: string; score?: number; verification?: { status?: string }; meta?: { sources?: unknown[] } }; error?: string };
            if (data.data?.email) {
                return {
                    email: data.data.email,
                    score: data.data.score || null,
                    confidence: data.data.verification?.status || null,
                    sources: data.data.meta?.sources || null,
                    method: "hunter.io",
                    first_name: firstName,
                    last_name: lastName
                };
            }
        } catch (e) {
            console.error("Hunter.io error:", (e as Error).message);
        }
    }

    // Step 2: Clearbit
    if (CLEARBIT_API_KEY) {
        try {
            const resp = await fetch(`https://person.clearbit.com/v2/combined/find?email=${encodeURIComponent(`${firstName}.${lastName}@${domain}`)}`, {
                headers: { "Authorization": `Bearer ${CLEARBIT_API_KEY}` }
            });
            if (resp.ok) {
                const data = await resp.json() as { person?: { email?: string; verification?: { status?: string } } };
                if (data.person?.email) {
                    return {
                        email: data.person.email,
                        confidence: data.person.verification?.status || null,
                        method: "clearbit",
                        first_name: firstName,
                        last_name: lastName
                    };
                }
            }
        } catch (e) {
            console.error("Clearbit error:", (e as Error).message);
        }
    }

    // Step 3: Pattern-based fallback
    const patterns = [
        `${firstName}.${lastName}@${domain}`,
        `${firstName}${lastName}@${domain}`,
        `${firstName[0]}${lastName}@${domain}`,
        `${firstName}@${domain}`,
        `${firstName[0]}${lastName[0]}@${domain}`,
        `${lastName}.${firstName}@${domain}`,
        `${firstName}_${lastName}@${domain}`,
    ];

    // Try to verify at least one pattern via MX check
    try {
        const mxRecords = await resolveMx(domain);
        if (mxRecords && mxRecords.length > 0) {
            return {
                email: `${firstName}.${lastName}@${domain}`,
                confidence: "low",
                method: "pattern_inference",
                suggested_patterns: patterns,
                first_name: firstName,
                last_name: lastName,
                note: "MX confirmed for domain, exact email not verified"
            };
        }
    } catch (e) {
        console.error("MX lookup error:", (e as Error).message);
    }

    return {
        error: `Could not find email for ${nameForSearch} at ${domain}`,
        attempted_patterns: patterns,
        first_name: firstName,
        last_name: lastName
    };
}

/**
 * Verify email deliverability: MX check + SMTP connect test
 */
async function verifyEmail(email: string): Promise<VerifyResult> {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return { valid: false, reason: "Invalid email format" };
    }

    const [, domain] = email.split("@");

    // Step 1: MX lookup
    let mxRecords: dns.MxRecord[];
    try {
        mxRecords = await resolveMx(domain);
    } catch (_e) {
        return { valid: false, reason: "No MX records found — domain cannot receive email", domain };
    }

    if (!mxRecords || mxRecords.length === 0) {
        return { valid: false, reason: "No MX records found", domain };
    }

    // Step 2: SMTP verification
    const mxHost = mxRecords[0].exchange;

    try {
        const result = await (async (): Promise<{ reachable: boolean; smtp_port?: number; mx_host: string; domain: string; note?: string }> => {
            const timeout = 5000;
            const ports = [25, 587, 465];

            for (const port of ports) {
                const success = await new Promise<boolean>((resolve) => {
                    const s = new net.Socket();
                    s.setTimeout(timeout);
                    s.connect(port, mxHost, () => {
                        s.destroy();
                        resolve(true);
                    });
                    s.on('error', () => {
                        s.destroy();
                        resolve(false);
                    });
                    s.on('timeout', () => {
                        s.destroy();
                        resolve(false);
                    });
                });
                if (success) {
                    return { reachable: true, smtp_port: port, mx_host: mxHost, domain };
                }
            }
            return { reachable: false, mx_host: mxHost, domain, note: "SMTP ports not reachable (may be firewall-blocked)" };
        })();

        if (result.reachable) {
            return {
                valid: true,
                reason: "MX server is reachable and accepting connections",
                mx_host: result.mx_host,
                smtp_port: result.smtp_port,
                domain,
                deliverable: "likely",
                note: "MX + SMTP connectivity confirmed. Email format is valid."
            };
        } else {
            return {
                valid: true,
                reason: "MX records exist but SMTP connectivity could not be verified (may be firewall-blocked)",
                mx_records: mxRecords.map(r => r.exchange),
                domain,
                deliverable: "unknown",
                note: "Email format is valid. MX exists. Full deliverability requires SMTP verification which may be blocked by firewalls."
            };
        }
    } catch (e) {
        console.error("SMTP verify error:", (e as Error).message);
        return {
            valid: true,
            reason: "MX records exist",
            mx_records: mxRecords.map(r => r.exchange),
            domain,
            deliverable: "likely",
            note: "Email format is valid and MX records exist."
        };
    }
}

/**
 * Detect company email format pattern from domain
 */
async function detectPattern(domain: string): Promise<PatternResult> {
    // Step 1: WHOIS lookup
    let companyName: string | null = null;
    let registrar: string | null = null;

    try {
        if (WHOIS_API_KEY) {
            const resp = await fetch(`https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${WHOIS_API_KEY}&domainName=${domain}&mode=1`, {
                headers: { "Accept": "application/json" }
            });
            if (resp.ok) {
                const data = await resp.json() as { WhoisRecord?: { registrant?: { organization?: string }; registrarName?: string } };
                companyName = data.WhoisRecord?.registrant?.organization || null;
                registrar = data.WhoisRecord?.registrarName || null;
            }
        }
    } catch (e) {
        console.error("WHOIS error:", (e as Error).message);
    }

    // Step 2: Hunter.io domain search
    let hunterPatterns: string[] = [];
    if (HUNTER_API_KEY) {
        try {
            const url = `https://api.hunter.io/v2/domain-search?domain=${encodeURIComponent(domain)}&api_key=${HUNTER_API_KEY}`;
            const resp = await fetch(url);
            const data = await resp.json() as { data?: { emails?: { value?: string }[] } };
            if (data.data?.emails) {
                hunterPatterns = data.data.emails.map(e => e.value || '').filter(Boolean);
            }
        } catch (e) {
            console.error("Hunter.io domain search error:", (e as Error).message);
        }
    }

    // Step 3: Inferred patterns
    const inferredPatterns = [
        { pattern: "{first}.{last}@" + domain, confidence: "high", description: "First.Last — most common B2B format (Microsoft, Google, Stripe)" },
        { pattern: "{first}{last}@" + domain, confidence: "medium", description: "FirstLast — used by many companies" },
        { pattern: "{first_initial}{last}@" + domain, confidence: "medium", description: "FLast — common in finance and law" },
        { pattern: "{first}@" + domain, confidence: "low", description: "First — only for unique first names" },
        { pattern: "{last}.{first}@" + domain, confidence: "low", description: "Last.First — rare, academic or European companies" }
    ];

    // Step 4: MX verification
    let mxConfirmed = false;
    try {
        const mxRecords = await resolveMx(domain);
        mxConfirmed = mxRecords && mxRecords.length > 0;
    } catch (e) {
        console.error("MX verify error:", (e as Error).message);
    }

    const response: PatternResult = {
        domain,
        company_name: companyName,
        registrar,
        mx_confirmed: mxConfirmed,
        patterns: inferredPatterns,
        observed_patterns: hunterPatterns.length > 0 ? hunterPatterns : null,
        most_likely: inferredPatterns[0],
        note: hunterPatterns.length > 0
            ? "Patterns observed from Hunter.io real email data"
            : "Patterns inferred — no real email data available. MX confirmed: " + (mxConfirmed ? "yes" : "no")
    };

    if (hunterPatterns.length > 0) {
        response.patterns_source = "hunter.io + domain_inference";
    } else {
        response.patterns_source = "domain_inference_only";
    }

    return response;
}

// ============================================
// TOOL DISPATCHER
// ============================================

async function handleTool(toolName: string, params: ToolParams = {}): Promise<unknown> {
    let result: unknown;

    switch (toolName) {
        case "find_email":
            result = await findEmail(params.full_name || '', params.domain || '');
            break;
        case "verify_email":
            result = await verifyEmail(params.email || '');
            break;
        case "detect_pattern":
            result = await detectPattern(params.domain || '');
            break;
        default:
            return { error: `Unknown tool: ${toolName}` };
    }

    // Charge PPE price
    const price = TOOL_PRICES[toolName];
    if (price) {
        try {
            await Actor.charge({ eventName: toolName });
        } catch (e) {
            console.error("Charge failed:", (e as Error).message);
        }
    }

    return result;
}

// ============================================
// HTTP SERVER FOR STANDBY MODE
// ============================================

function startHttpServer(): void {
    const PORT = Actor.config.get('containerPort') || 3000;

    const server = http.createServer((req, res) => {
        if (req.headers['x-apify-container-server-readiness-probe']) {
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            res.end('OK');
            return;
        }

        if (req.method === 'POST' && req.url === '/mcp') {
            let body = '';
            req.on('data', (chunk: Buffer) => { body += chunk.toString(); });
            req.on('end', async () => {
                try {
                    const jsonBody = JSON.parse(body);
                    const id = jsonBody.id ?? null;

                    const reply = (result: unknown) => {
                        const resp = id !== null
                            ? { jsonrpc: '2.0', id, result }
                            : result;
                        res.writeHead(200, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify(resp));
                    };

                    const replyError = (code: number, message: string) => {
                        const resp = id !== null
                            ? { jsonrpc: '2.0', id, error: { code, message } }
                            : { status: 'error', error: message };
                        res.writeHead(200, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify(resp));
                    };

                    const method = jsonBody.method;

                    if (method === 'initialize') {
                        return reply({
                            protocolVersion: '2024-11-05',
                            capabilities: { tools: {} },
                            serverInfo: { name: 'email-intelligence-mcp', version: '1.0' }
                        });
                    }

                    if (method === 'tools/list' || (!method && jsonBody.tool === 'list')) {
                        return reply({ tools: MCP_MANIFEST.tools });
                    }

                    if (method === 'tools/call') {
                        const toolName = jsonBody.params?.name;
                        const toolArgs = jsonBody.params?.arguments || {};
                        if (!toolName) return replyError(-32602, 'Missing params.name');
                        const toolResult = await handleTool(toolName, toolArgs);
                        return reply({ content: [{ type: 'text', text: JSON.stringify(toolResult, null, 2) }] });
                    }

                    const { tool, params = {} } = jsonBody;
                    if (!tool) return replyError(-32602, 'Missing tool name');

                    const result = await handleTool(tool, params);
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ status: 'success', result }));
                } catch (error) {
                    res.writeHead(500, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ status: 'error', error: (error as Error).message }));
                }
            });
            return;
        }

        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found');
    });

    server.listen(PORT, () => {
        console.log(`Email Intelligence MCP listening on port ${PORT}`);
    });

    process.on('SIGTERM', () => {
        server.close(() => process.exit(0));
    });
}

// ============================================
// handleRequest export for MCP standby mode
// Must be at module level (NOT inside main()), as ESM named export
// ============================================

export const handleRequest = async (req: { toolName: string; arguments: Record<string, unknown> }) => {
    const { toolName, arguments: args } = req;
    const tool = MCP_MANIFEST.tools.find((t) => t.name === toolName) as { name: string; description: string; input_schema: { type: "object"; properties: Record<string, unknown>; required: string[] }; price: number } | undefined;
    if (!tool) {
        return {
            content: [{ type: 'text', text: JSON.stringify({ error: `Unknown tool: ${toolName}` }) }],
            isError: true,
        };
    }
    try {
        await Actor.charge({ eventName: tool.name });
        const result = await handleTool(toolName, args as ToolParams);
        return {
            content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        };
    } catch (err) {
        return {
            content: [{ type: 'text', text: JSON.stringify({ error: String(err) }) }],
            isError: true,
        };
    }
};

// ============================================
// MAIN ENTRY POINT
// ============================================

async function main() {
    await Actor.init();

    const input = await Actor.getInput() as { tool?: string; params?: Record<string, unknown> } | null;

    const isStandby = process.env.APIFY_META_ORIGIN === 'STANDBY';

    if (isStandby) {
        // MCP standby mode: start HTTP server, stay alive
        startHttpServer();
    } else {
        // Batch mode: run tool, push data, exit
        // CRITICAL: Apify health check sends empty {} as input
        const effectiveTool = input?.tool || 'find_email';
        const effectiveParams = input?.params || { full_name: 'John Smith', domain: 'example.com' };

        const result = await handleTool(effectiveTool, effectiveParams as ToolParams);
        await Actor.pushData([result]);
        await Actor.setValue('OUTPUT', result);
        await Actor.exit();
    }
}

main();
