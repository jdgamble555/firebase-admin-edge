import { createServer } from 'node:http';
import { build } from 'esbuild';
import { chromium } from '../app-demo/node_modules/playwright/index.mjs';

const bundle = await build({
    entryPoints: ['validation/runtime-checks.ts'],
    bundle: true,
    write: false,
    format: 'iife',
    globalName: 'runtimeChecks',
    platform: 'browser',
    target: 'es2022'
});
const server = createServer((_request, response) => {
    response.writeHead(200, {
        'Content-Type': 'text/html',
        'Content-Security-Policy':
            "default-src 'none'; script-src 'unsafe-inline'; connect-src 'none'"
    });
    response.end('<!doctype html><title>Local runtime validation</title>');
});
let browser;
try {
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    await page.goto(`http://127.0.0.1:${address.port}`);
    await page.addScriptTag({ content: bundle.outputFiles[0].text });
    const result = await page.evaluate(() => runtimeChecks.checkWebRuntime());
    console.log(JSON.stringify({ runtime: 'Chromium', checks: result }));
} finally {
    if (browser) await browser.close();
    server.close();
}
