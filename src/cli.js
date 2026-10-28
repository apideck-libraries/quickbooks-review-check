import fs from 'node:fs';
import { parseArgs } from 'node:util';
import { runRuntime } from './runtime.js';
import { scanSource } from './source.js';
import { toConsole, toMarkdown, toJson, summarize } from './report.js';

const HELP = `quickbooks-review-check — free self-check for the Intuit QuickBooks Online app security review

Usage:
  quickbooks-review-check --url https://app.example.com --callback /oauth/callback [--source .]
  quickbooks-review-check --source ./my-app

Runtime checks (probe your deployed app):
  --url <url>            Base URL of your deployed app
  --callback <path>      OAuth redirect URI path (checks the 302 rule, cache headers, cookies)
  --path <path>          Sensitive page to check for no-store caching (repeatable)
  --header "K: V"        Extra request header, e.g. an authenticated session cookie (repeatable)
  --timeout <ms>         Per-request timeout (default 10000)
  --http-port <port>     Port for the plain-HTTP redirect check (default 80; for local testing)

Source checks (static scan of your code):
  --source <dir>         Scan a repository for token-handling issues
  --include-tests        Also scan test/example files

Output:
  --markdown <file>      Write a Markdown report ("-" for stdout)
  --json <file>          Write a JSON report ("-" for stdout)
  --fail-on <level>      Exit 1 on: fail (default) | warn | never
  -q, --quiet            Don't print the console report
  -h, --help
`;

export async function main(argv) {
  let args;
  try {
    ({ values: args } = parseArgs({
      args: argv,
      options: {
        url: { type: 'string' },
        callback: { type: 'string' },
        path: { type: 'string', multiple: true, default: [] },
        header: { type: 'string', multiple: true, default: [] },
        timeout: { type: 'string', default: '10000' },
        'http-port': { type: 'string' },
        source: { type: 'string' },
        'include-tests': { type: 'boolean', default: false },
        markdown: { type: 'string' },
        json: { type: 'string' },
        'fail-on': { type: 'string', default: 'fail' },
        quiet: { type: 'boolean', short: 'q', default: false },
        verbose: { type: 'boolean', short: 'v', default: false },
        help: { type: 'boolean', short: 'h', default: false },
      },
    }));
  } catch (e) {
    console.error(`${e.message}\n\n${HELP}`);
    return 2;
  }
  if (args.help || (!args.url && !args.source)) {
    console.log(HELP);
    return args.help ? 0 : 2;
  }

  const headers = {};
  for (const h of args.header) {
    const i = h.indexOf(':');
    if (i > 0) headers[h.slice(0, i).trim().toLowerCase()] = h.slice(i + 1).trim();
  }
  const log = args.verbose ? (m) => console.error(`· ${m}`) : () => {};

  const results = [];
  if (args.url) {
    const url = /^https?:\/\//.test(args.url) ? args.url : `https://${args.url}`;
    results.push(...(await runRuntime({ url, paths: args.path, callback: args.callback, headers, timeout: Number(args.timeout), log, httpPort: args['http-port'] ? Number(args['http-port']) : undefined })));
  }
  if (args.source) {
    const { results: src, scanned } = scanSource(args.source, { includeTests: args['include-tests'] });
    log(`scanned ${scanned} files`);
    results.push(...src);
  }

  const report = { target: args.url, source: args.source, results };
  if (!args.quiet) console.log(toConsole(report));
  writeOut(args.markdown, () => toMarkdown(report));
  writeOut(args.json, () => toJson(report));
  if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${toMarkdown(report)}\n`);

  const c = summarize(results);
  if (args['fail-on'] === 'never') return 0;
  if (c.fail || (args['fail-on'] === 'warn' && c.warn)) return 1;
  return 0;
}

function writeOut(dest, render) {
  if (!dest) return;
  if (dest === '-') process.stdout.write(`${render()}\n`);
  else fs.writeFileSync(dest, render());
}
