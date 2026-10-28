#!/usr/bin/env node
import { main } from '../src/cli.js';

// exitCode rather than process.exit(), so piped stdout (e.g. `--json - | jq`) is fully flushed.
main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    console.error(err);
    process.exitCode = 2;
  },
);
