import { firestoreData } from '../src/db/firestore-results.js';
import {
    Firestore,
    Timestamp,
    Bytes,
    Query,
    QuerySnapshot,
    FieldValue
} from '../src/db/firestore.js';
import type { ServiceAccount } from '../src/auth/firebase-types.js';
import { StorageCrc32c } from '../src/storage/storage-checksum.js';
import {
    Storage,
    calculateStorageCrc32c,
    calculateStorageMd5
} from '../src/storage/storage.js';

function check(condition: unknown, message: string): asserts condition {
    if (!condition) {
        throw new Error(message);
    }
}

/** Exercise web-only primitives without credentials or a network dependency. */
export async function checkWebRuntime(): Promise<string[]> {
    const db = new Firestore({
        project_id: 'local-validation'
    } as ServiceAccount);
    const name =
        'projects/local-validation/databases/(default)/documents/items/a';
    const time = '2026-01-01T00:00:00.123456789Z';
    const document = {
        name,
        createTime: time,
        updateTime: time,
        fields: {
            label: { stringValue: 'é😀' },
            bytes: { bytesValue: 'AP8=' },
            time: { timestampValue: time },
            count: { integerValue: '42' }
        }
    };
    const snapshot = db.snapshot_(document, time, 'json');
    check(snapshot.get('label') === 'é😀', 'Unicode decoding');
    check(
        (snapshot.get('bytes') as Bytes).toUint8Array()[1] === 255,
        'Byte decoding'
    );
    check(
        (snapshot.get('time') as Timestamp).nanoseconds === 123456789,
        'Nanosecond precision'
    );
    const query = db.collection('items').orderBy('label');
    const querySnapshot = new QuerySnapshot(
        query,
        [snapshot],
        snapshot.readTime
    );
    const bytes = db
        .bundle('browser-validation')
        .add(snapshot)
        .add('items', querySnapshot)
        .build();
    let offset = 0;
    let metadataEnd = 0;
    const records: Record<string, any>[] = [];
    while (offset < bytes.length) {
        let prefix = '';
        while (offset < bytes.length && bytes[offset] !== 123)
            prefix += String.fromCharCode(bytes[offset++]!);
        check(/^\d+$/.test(prefix), 'Bundle length prefix');
        const size = Number(prefix);
        check(size > 0 && offset + size <= bytes.length, 'Bundle byte bounds');
        records.push(
            JSON.parse(
                new TextDecoder('utf-8', { fatal: true }).decode(
                    bytes.slice(offset, offset + size)
                )
            )
        );
        offset += size;
        if (records.length === 1) metadataEnd = offset;
    }
    check(
        records[0]?.metadata.totalBytes === bytes.length - metadataEnd,
        'Bundle byte count'
    );
    check(records[0]?.metadata.totalDocuments === 1, 'Bundle deduplication');
    check(
        records.find((record) => record.document)?.document.fields.label
            .stringValue === 'é😀',
        'Bundle Unicode payload'
    );
    check(
        records.find((record) => record.namedQuery)?.namedQuery.name ===
            'items',
        'Bundle named query'
    );
    check(
        records
            .find((record) => record.documentMetadata)
            ?.documentMetadata.queries.includes('items'),
        'Bundle membership'
    );
    const streamed = new ReadableStream<Uint8Array>({
        start(controller) {
            controller.enqueue(bytes);
            controller.close();
        }
    });
    const roundTrip = await new Response(streamed).arrayBuffer();
    check(roundTrip.byteLength === bytes.byteLength, 'Web stream round trip');
    const key = await crypto.subtle.generateKey(
        {
            name: 'RSASSA-PKCS1-v1_5',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256'
        },
        true,
        ['sign', 'verify']
    );
    const signature = await crypto.subtle.sign(
        'RSASSA-PKCS1-v1_5',
        key.privateKey,
        bytes
    );
    const valid = await crypto.subtle.verify(
        'RSASSA-PKCS1-v1_5',
        key.publicKey,
        signature,
        bytes
    );
    check(valid, 'Web Crypto RSA support');
    const exportedKey = await crypto.subtle.exportKey('pkcs8', key.privateKey);
    const pemBody = btoa(String.fromCharCode(...new Uint8Array(exportedKey)));
    const checksum = await calculateStorageCrc32c('123456789');
    check(checksum === '4waSgw==', 'Storage web CRC32C');
    const md5 = await calculateStorageMd5('abc');
    check(md5 === 'kAFQmDzST7DWlj99KOF/cg==', 'Storage web MD5');
    let storageReads = 0;
    let uploadedBytes = 0;
    const fileChecksum = await calculateStorageCrc32c(
        new Uint8Array([1, 2, 3])
    );
    const fileMd5 = await calculateStorageMd5(new Uint8Array([1, 2, 3]));
    const partialBytes = new Uint8Array(262144).fill(42);
    const partialChecksum = await calculateStorageCrc32c(partialBytes);
    const finalPartialChecksum = new StorageCrc32c(partialChecksum);
    finalPartialChecksum.update(new Uint8Array([1, 2, 3]));
    const storage = new Storage(
        {
            project_id: 'runtime-check',
            client_email: 'runtime@example.com',
            private_key: `-----BEGIN PRIVATE KEY-----\n${pemBody}\n-----END PRIVATE KEY-----`
        } as ServiceAccount,
        {
            bucketName: 'runtime-bucket',
            fetch: async (_input, init) => {
                if (init?.method === 'POST') {
                    return new Response(null, {
                        headers: {
                            Location:
                                'https://storage.googleapis.com/upload/storage/v1/b/runtime-bucket/o?upload_id=automated'
                        }
                    });
                }
                if (init?.method === 'PUT') {
                    const range = new Headers(init.headers).get(
                        'content-range'
                    );
                    if (
                        range?.endsWith('/*') ||
                        range?.startsWith('bytes */')
                    ) {
                        return new Response(null, {
                            status: 308,
                            headers: { Range: 'bytes=0-262143' }
                        });
                    }
                    if (range?.startsWith('bytes 262144-')) {
                        return Response.json({
                            name: 'partial',
                            bucket: 'runtime-bucket',
                            generation: '1',
                            size: '262147',
                            crc32c: finalPartialChecksum.digest()
                        });
                    }
                    return Response.json({
                        name: 'file',
                        bucket: 'runtime-bucket',
                        generation: '1',
                        size: '3',
                        crc32c: fileChecksum,
                        md5Hash: fileMd5
                    });
                }
                storageReads++;
                if (storageReads === 1) {
                    return new Response(null, { status: 503 });
                }
                return new Response(
                    new ReadableStream<Uint8Array>({
                        start(controller) {
                            controller.enqueue(new Uint8Array([1, 2, 3]));
                            controller.close();
                        }
                    }),
                    {
                        headers: {
                            'x-goog-hash': `crc32c=${fileChecksum},md5=${fileMd5}`
                        }
                    }
                );
            },
            cache: {
                getCache: <T>() => ({ access_token: 'local' }) as T,
                setCache: () => {}
            }
        }
    );
    const { error: signingError, data: signedUrl } = await storage.getSignedUrl(
        'file',
        { action: 'read' }
    );
    check(
        !signingError && signedUrl?.includes('X-Goog-Signature='),
        'Storage URL signing'
    );
    const { error: streamingError, data: streamedFile } =
        await storage.downloadStream('file', { verifyChecksum: true });
    check(
        !streamingError && streamedFile && !streamedFile.bodyUsed,
        'Storage streaming response'
    );
    const streamedBytes = await streamedFile.arrayBuffer();
    check(streamedBytes.byteLength === 3, 'Storage streaming content');
    check(storageReads === 2, 'Storage retries transient reads');
    const { error: chunkError, data: uploadedChunk } =
        await storage.uploadChunk(
            'https://storage.googleapis.com/upload/storage/v1/b/runtime-bucket/o?upload_id=local',
            new Uint8Array([1, 2, 3]),
            {
                offset: 0,
                totalSize: 3,
                onProgress: ({ bytesTransferred }) => {
                    uploadedBytes = bytesTransferred;
                }
            }
        );
    check(
        !chunkError && uploadedChunk?.complete,
        'Storage resumable web bodies'
    );
    check(uploadedBytes === 3, 'Storage upload progress');
    const { error: automatedError, data: automated } =
        await storage.uploadStream(
            'file',
            new Blob([new Uint8Array([1, 2, 3])]).stream()
        );
    check(
        !automatedError && automated?.crc32c === fileChecksum,
        'Storage automated stream uploads'
    );
    let customUpdates = 0;
    const reference = storage.bucket().file('file', {
        crc32cGenerator: () => ({
            update() {
                customUpdates++;
            },
            toString() {
                return fileChecksum;
            },
            validate(value) {
                return value === fileChecksum;
            }
        })
    });
    const { error: md5SaveError } = await reference.save(
        new Uint8Array([1, 2, 3]),
        { validation: 'md5' }
    );
    check(!md5SaveError, 'Storage File MD5 upload');
    const md5Bytes = await new Response(
        reference.stream({ validation: 'md5' })
    ).arrayBuffer();
    check(md5Bytes.byteLength === 3, 'Storage File MD5 stream');
    const referenceBytes = await new Response(
        reference.createReadStream({ validation: 'crc32c' })
    ).arrayBuffer();
    check(referenceBytes.byteLength === 3, 'Storage File Web Stream');
    check(customUpdates > 0, 'Storage custom CRC32C hook');
    const partialFile = storage
        .bucket()
        .file('partial', { crc32cGenerator: () => new StorageCrc32c() });
    const partialWritable = partialFile.createWriteStream({
        isPartialUpload: true,
        chunkSize: 262144
    });
    await new Blob([partialBytes]).stream().pipeTo(partialWritable);
    const { error: partialError, data: checkpoint } =
        await partialWritable.result;
    check(
        !partialError &&
            checkpoint?.crc32c === partialChecksum &&
            checkpoint.nextOffset === 262144,
        'Storage partial checkpoint'
    );
    const { error: resumeError } = await partialFile.save(
        new Uint8Array([1, 2, 3]),
        {
            uri: checkpoint.sessionUri,
            offset: checkpoint.nextOffset,
            resumeCRC32C: checkpoint.crc32c
        }
    );
    check(
        !resumeError && partialFile.metadata?.size === '262147',
        'Storage custom CRC32C partial resume'
    );
    const writable = reference.createWriteStream();
    const writer = writable.getWriter();
    await writer.write(new Uint8Array([1, 2, 3]));
    await writer.close();
    const { error: writeError, data: written } = await writable.result;
    check(
        !writeError && written?.crc32c === fileChecksum,
        'Storage File writable completion result'
    );
    const { error: referenceSignError, data: referenceSignedUrl } =
        await reference.getSignedUrl({
            action: 'read',
            version: 'v2',
            expires: Date.now() + 60000
        });
    check(
        !referenceSignError && referenceSignedUrl?.includes('GoogleAccessId='),
        'Storage File V2 URL signing'
    );
    const { error: xmlError, data: xmlRequest } = await storage.signXmlRequest({
        method: 'GET',
        name: 'file'
    });
    check(
        !xmlError &&
            xmlRequest?.headers
                .get('Authorization')
                ?.startsWith('GOOG4-RSA-SHA256 '),
        'Storage XML request signing'
    );
    let reads = 0;
    let stop = () => {};
    const polling = new Query(db, 'items', async () => {
        reads++;
        const telemetryKey = Symbol.for('opentelemetry.js.api.1');
        const previousTelemetry = Object.getOwnPropertyDescriptor(
            globalThis,
            telemetryKey
        );
        const traceNames: string[] = [];
        const completed: string[] = [];
        try {
            Object.defineProperty(globalThis, telemetryKey, {
                configurable: true,
                value: {
                    version: '1.9.0',
                    trace: {
                        getTracer: () => ({
                            startSpan: (name: string) => {
                                traceNames.push(name);
                                return {
                                    end: () => {
                                        completed.push(name);
                                    }
                                };
                            }
                        })
                    }
                }
            });
            const traced = new Query(db, 'items', async () => [document]);
            const result = await traced.get().then(firestoreData);
            check(result.docs.length === 1, 'Tracing preserves query results');
            check(
                traceNames.includes('Query.get') &&
                    completed.includes('Query.get'),
                'Global telemetry without Node dependencies'
            );
        } finally {
            if (previousTelemetry)
                Object.defineProperty(
                    globalThis,
                    telemetryKey,
                    previousTelemetry
                );
            else Reflect.deleteProperty(globalThis, telemetryKey);
        }
        return [document];
    });
    await new Promise<void>((resolve, reject) => {
        const deadline = setTimeout(() => {
            stop();
            reject(new Error('Polling callback timed out'));
        }, 5000);
        stop = polling.onSnapshot(
            { pollIntervalMs: 10 },
            (result) => {
                clearTimeout(deadline);
                stop();
                if (result.size !== 1) {
                    reject(new Error('Polling snapshot mismatch'));
                    return;
                }
                resolve();
            },
            (error) => {
                clearTimeout(deadline);
                reject(error);
            }
        );
    });
    check(reads === 1, 'Polling initial read and unsubscribe');
    await db.terminate().then(firestoreData);
    return [
        'snapshot decoding',
        'bundle framing and metadata',
        'web streams',
        'Web Crypto RSA',
        'polling cleanup',
        'global telemetry',
        'Storage signing, streaming, resumable uploads, retries, CRC32C, and progress'
    ];
}

/** Run from the local worker only; credentials never enter the browser. */
export async function checkLiveEdge(
    account: ServiceAccount,
    database = '(default)'
): Promise<string[]> {
    if (!account?.project_id || !account.private_key || !account.client_email)
        throw new Error('Missing service-account configuration');
    const db = new Firestore(account, { databaseId: database });
    const root = db.doc(`firebase_admin_edge_tests/${crypto.randomUUID()}`);
    try {
        await root
            .create({
                runtime: 'local-workerd',
                n: 1,
                time: FieldValue.serverTimestamp()
            })
            .then(firestoreData);
        const read = await root.get().then(firestoreData);
        check(
            read.get('n') === 1 && read.get('time') instanceof Timestamp,
            'Live read/write'
        );
        await db
            .runTransaction(async (transaction) => {
                const before = await transaction.get(root).then(firestoreData);
                transaction.update(root, { n: Number(before.get('n')) + 1 });
            })
            .then(firestoreData);
        const updated = await root.get().then(firestoreData);
        check(updated.get('n') === 2, 'Live transaction');
        const writer = db.bulkWriter({ throttling: false });
        const pending = [
            writer
                .set(root.collection('items').doc('a'), { n: 1 })
                .then(firestoreData),
            writer
                .set(root.collection('items').doc('b'), { n: 2 })
                .then(firestoreData)
        ];
        const results = Promise.all(pending);
        await writer.close().then(firestoreData);
        await results;
        const query = root.collection('items').orderBy('n');
        const snapshot = await query.get().then(firestoreData);
        check(snapshot.size === 2, 'Live query and bulk writes');
        const explanation = await query
            .explain({ analyze: true })
            .then(firestoreData);
        check(
            explanation.metrics.executionStats?.resultsReturned === 2,
            'Live explain'
        );
        const reader = query.stream().getReader();
        let count = 0;
        try {
            for (;;) {
                const item = await reader.read();
                if (item.done) break;
                count++;
            }
        } finally {
            reader.releaseLock();
        }
        check(count === 2, 'Live streaming');
        check(
            db.bundle().add('items', snapshot).build().length > 0,
            'Live bundle generation'
        );
        return [
            'OAuth signing',
            'live reads/writes',
            'transactions',
            'bulk writes',
            'queries/explain',
            'streaming',
            'bundles',
            'cleanup'
        ];
    } finally {
        try {
            await db.recursiveDelete(root).then(firestoreData);
        } catch {
            throw new Error(`Cleanup failed: ${root.path}`);
        } finally {
            await db.terminate().then(firestoreData);
        }
    }
}
