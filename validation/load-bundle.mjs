import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { build } from 'esbuild';
import { chromium } from '../app-demo/node_modules/playwright/index.mjs';

// Load the independent consumer from the official CDN, without installing it.
const sdkVersion = '12.19.0';
const compiled = await build({
    entryPoints: ['src/db/firestore.ts'],
    bundle: true,
    write: false,
    format: 'iife',
    globalName: 'edgeFirestore',
    platform: 'browser',
    target: 'es2022'
});
const server = createServer((_request, response) => {
    response.writeHead(200, {
        'Content-Type': 'text/html',
        'Content-Security-Policy':
            "default-src 'none'; script-src 'unsafe-inline' https://www.gstatic.com; connect-src 'none'"
    });
    response.end(
        '<!doctype html><title>Bundle interoperability validation</title>'
    );
});
let browser;
try {
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    const unexpectedRequests = [];
    await page.route('**/*', (route) => {
        const url = new URL(route.request().url());
        if (
            url.hostname === '127.0.0.1' ||
            (url.origin === 'https://www.gstatic.com' &&
                url.pathname.startsWith(`/firebasejs/${sdkVersion}/`))
        )
            return route.continue();
        unexpectedRequests.push(url.origin);
        return route.abort();
    });
    await page.goto(`http://127.0.0.1:${server.address().port}`);
    await page.addScriptTag({ content: compiled.outputFiles[0].text });
    const results = await page.evaluate(async (version) => {
        const appSdk = await import(
            `https://www.gstatic.com/firebasejs/${version}/firebase-app.js`
        );
        const sdk = await import(
            `https://www.gstatic.com/firebasejs/${version}/firebase-firestore.js`
        );
        const projectId = 'local-bundle-validation';
        const app = appSdk.initializeApp({
            projectId,
            apiKey: 'unused-local-key',
            appId: 'local-bundle-test'
        });
        const client = sdk.initializeFirestore(app, {
            localCache: sdk.memoryLocalCache()
        });
        const source = new edgeFirestore.Firestore({ project_id: projectId });
        await sdk.disableNetwork(client);
        try {
            const time = '2026-01-01T00:00:00.123456789Z';
            const prefix = `projects/${projectId}/databases/(default)/documents/items/`;
            const a = source.snapshot_(
                {
                    name: prefix + 'a',
                    createTime: time,
                    updateTime: time,
                    fields: {
                        rank: { integerValue: '1' },
                        label: { stringValue: 'é😀' },
                        bytes: { bytesValue: 'AP8=' },
                        time: { timestampValue: time },
                        point: { geoPointValue: { latitude: 1, longitude: 2 } },
                        link: { referenceValue: prefix + 'b' },
                        nested: {
                            mapValue: {
                                fields: {
                                    list: {
                                        arrayValue: {
                                            values: [
                                                { nullValue: null },
                                                { booleanValue: true }
                                            ]
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                time,
                'json'
            );
            const b = source.snapshot_(
                {
                    name: prefix + 'b',
                    createTime: time,
                    updateTime: time,
                    fields: { rank: { integerValue: '2' } }
                },
                time,
                'json'
            );
            const missing = source.snapshot_(prefix + 'missing', time, 'json');
            const query = source.collection('items').orderBy('rank');
            const all = new edgeFirestore.QuerySnapshot(
                query,
                [a, b],
                a.readTime
            );
            const last = new edgeFirestore.QuerySnapshot(
                query.limitToLast(1),
                [b],
                b.readTime
            );
            const empty = new edgeFirestore.QuerySnapshot(
                source.collection('empty'),
                [],
                a.readTime
            );
            const data = source
                .bundle('interop')
                .add(a)
                .add(missing)
                .add('all', all)
                .add('last', last)
                .add('empty', empty)
                .build();
            const progress = await sdk.loadBundle(client, data);
            const cached = await sdk.getDocFromCache(
                sdk.doc(client, 'items/a')
            );
            const value = cached.data();
            const absent = await sdk.getDocFromCache(
                sdk.doc(client, 'items/missing')
            );
            const queries = {};
            for (const name of ['all', 'last', 'empty']) {
                const restored = await sdk.namedQuery(client, name);
                if (!restored) throw new Error(`Named query missing: ${name}`);
                const docs = await sdk.getDocsFromCache(restored);
                queries[name] = docs.docs.map((doc) => doc.id);
            }
            const repeat = await sdk.loadBundle(client, data);
            const emptyProgress = await sdk.loadBundle(
                client,
                source.bundle('empty-bundle').build()
            );
            return {
                taskState: progress.taskState,
                documentsLoaded: progress.documentsLoaded,
                exists: cached.exists(),
                label: value.label,
                rank: value.rank,
                bytes: Array.from(value.bytes.toUint8Array()),
                nanos: value.time.nanoseconds,
                point: [value.point.latitude, value.point.longitude],
                reference: value.link.path,
                nested: value.nested,
                missingExists: absent.exists(),
                queries,
                repeat: repeat.taskState,
                empty: emptyProgress.taskState
            };
        } finally {
            await sdk.terminate(client);
            await appSdk.deleteApp(app);
            await source.terminate();
        }
    }, sdkVersion);
    assert.deepEqual(results, {
        taskState: 'Success',
        documentsLoaded: 3,
        exists: true,
        label: 'é😀',
        rank: 1,
        bytes: [0, 255],
        nanos: 123456789,
        point: [1, 2],
        reference: 'items/b',
        nested: { list: [null, true] },
        missingExists: false,
        queries: { all: ['a', 'b'], last: ['b'], empty: [] },
        repeat: 'Success',
        empty: 'Success'
    });
    assert.deepEqual(unexpectedRequests, []);
    console.log(
        JSON.stringify({
            sdkVersion,
            runtime: 'Chromium',
            result: 'passed',
            checks: [
                'loadBundle',
                'typed cached documents',
                'missing documents',
                'named queries',
                'limitToLast',
                'empty query',
                'duplicate load',
                'empty bundle'
            ],
            firestoreNetwork: 'disabled'
        })
    );
} finally {
    if (browser) await browser.close();
    server.close();
}
