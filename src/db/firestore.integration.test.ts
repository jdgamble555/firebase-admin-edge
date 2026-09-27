import { firestoreData } from './firestore-results.js';
import { field } from './pipeline.js';
import { readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
    Firestore,
    FieldValue,
    Timestamp,
    Bytes,
    GeoPoint,
    AggregateField,
    VectorValue
} from './firestore.js';
import type { ServiceAccount } from '../auth/firebase-types.js';

describe.skipIf(process.env.FIRESTORE_LIVE_TESTS !== '1')(
    'live Firestore REST integration',
    () => {
        const runId = randomUUID();
        const rootPath = `firebase_admin_edge_tests/${runId}`;
        let db: Firestore | undefined;
        const requests: string[] = [];

        beforeAll(async () => {
            if (process.env.FIRESTORE_EMULATOR_HOST)
                throw new Error(
                    'Live tests require a real project. Unset FIRESTORE_EMULATOR_HOST.'
                );
            let account: ServiceAccount;
            try {
                const raw =
                    process.env.PRIVATE_FIREBASE_ADMIN_CONFIG ??
                    (process.env.GOOGLE_APPLICATION_CREDENTIALS
                        ? readFileSync(
                              process.env.GOOGLE_APPLICATION_CREDENTIALS,
                              'utf8'
                          )
                        : '');
                account = JSON.parse(raw);
            } catch {
                throw new Error(
                    'Provide PRIVATE_FIREBASE_ADMIN_CONFIG in .env or GOOGLE_APPLICATION_CREDENTIALS pointing to a service-account JSON file.'
                );
            }
            if (
                !account?.project_id ||
                !account.client_email ||
                !account.private_key
            )
                throw new Error(
                    'The live-test service account is missing project_id, client_email or private_key.'
                );
            db = new Firestore(
                account,
                process.env.FIRESTORE_TEST_DATABASE_ID ?? '(default)',
                async (input, init) => {
                    requests.push(String(input));
                    const deadline = AbortSignal.timeout(20000);
                    const signal = init?.signal
                        ? AbortSignal.any([init.signal, deadline])
                        : deadline;
                    return fetch(input, { ...init, signal });
                }
            );
            console.info(`Live Firestore test data: ${rootPath}`);
            await db
                .doc(rootPath)
                .create({
                    integrationTest: true,
                    createdAt: FieldValue.serverTimestamp()
                })
                .then(firestoreData);
        });

        afterAll(async () => {
            if (!db) return;
            try {
                await db.recursiveDelete(db.doc(rootPath)).then(firestoreData);
                const removed = await db
                    .doc(rootPath)
                    .get()
                    .then(firestoreData);
                expect(removed.exists).toBe(false);
            } catch {
                throw new Error(
                    `Live-test cleanup failed. Remove only this test subtree: ${rootPath}`
                );
            } finally {
                await db.terminate().then(firestoreData);
            }
        });

        it('applies minimum and maximum transforms against the service', async () => {
            const ref = db!.doc(`${rootPath}/extrema/value`);
            await ref.set({ low: 5, high: 5 }).then(firestoreData);
            const write = await ref
                .update({
                    low: FieldValue.minimum(2),
                    high: FieldValue.maximum(8),
                    missing: FieldValue.minimum(3)
                })
                .then(firestoreData);
            expect(write.isEqual(write)).toBe(true);
            const snapshot = await ref.get().then(firestoreData);
            expect(snapshot.data()).toEqual({ low: 2, high: 8, missing: 3 });
        });
        it.skipIf(process.env.FIRESTORE_PIPELINE_TESTS !== '1')(
            'executes pipeline projections and aggregation against the service',
            async () => {
                const collection = db!.collection(`${rootPath}/pipelines`);
                await collection
                    .doc('a')
                    .set({ label: 'A', n: 2 })
                    .then(firestoreData);
                const base = db!.pipeline().collection(collection);
                const snapshot = await base
                    .where(field('n').greaterThan(0))
                    .select('label', field('n').multiply(2).as('doubled'))
                    .execute()
                    .then(firestoreData);
                expect(snapshot.results.map((result) => result.data())).toEqual(
                    [{ label: 'A', doubled: 4 }]
                );
                const aggregate = await base
                    .aggregate(field('n').sum().as('total'))
                    .execute()
                    .then(firestoreData);
                expect(aggregate.results[0]!.get('total')).toBe(2);
            }
        );
        it('round-trips values, masks, transforms, metadata and write preconditions', async () => {
            const ref = db!.doc(`${rootPath}/crud/value`);
            const time = new Timestamp(1700000000, 123456000);
            await ref
                .create({
                    text: 'live é test',
                    integer: 42,
                    bytes: Bytes.fromUint8Array(new Uint8Array([0, 255])),
                    point: new GeoPoint(1, 2),
                    time,
                    link: ref,
                    array: [1, 'two'],
                    nested: { active: true },
                    nil: null
                })
                .then(firestoreData);
            const snapshot = await ref.get().then(firestoreData);
            expect(snapshot.exists).toBe(true);
            expect(snapshot.get('text')).toBe('live é test');
            expect(snapshot.get('bytes')).toEqual(
                Bytes.fromUint8Array(new Uint8Array([0, 255]))
            );
            expect(snapshot.get('point')).toEqual(new GeoPoint(1, 2));
            expect(snapshot.get('time')).toEqual(time);
            expect((snapshot.get('link') as typeof ref).isEqual(ref)).toBe(
                true
            );
            expect(snapshot.createTime).toBeInstanceOf(Timestamp);
            expect(snapshot.updateTime).toBeInstanceOf(Timestamp);
            expect(snapshot.readTime).toBeInstanceOf(Timestamp);
            await expect(
                ref.create({}).then(firestoreData)
            ).rejects.toMatchObject({
                code: 'firestore/already-exists'
            });
            await ref
                .update(
                    'integer',
                    FieldValue.increment(2),
                    'nested.active',
                    false,
                    { lastUpdateTime: snapshot.updateTime! }
                )
                .then(firestoreData);
            await expect(
                ref
                    .update(
                        { integer: 0 },
                        { lastUpdateTime: snapshot.updateTime! }
                    )
                    .then(firestoreData)
            ).rejects.toMatchObject({ code: 'firestore/failed-precondition' });
            const masked = await db!
                .getAll(ref, db!.doc(`${rootPath}/crud/missing`), {
                    fieldMask: ['integer']
                })
                .then(firestoreData);
            expect(masked[0]!.data()).toEqual({ integer: 44 });
            expect(masked[1]!.exists).toBe(false);
        });

        it('executes ordered queries, aggregation, streaming and explain against the service', async () => {
            const collection = db!.collection(`${rootPath}/queries`);
            const batch = db!.batch();
            for (let n = 1; n <= 3; n++)
                batch.set(collection.doc(String(n)), { n });
            await batch.commit().then(firestoreData);
            const query = collection.orderBy('n');
            const result = await query.get().then(firestoreData);
            expect(result.docs.map((doc) => doc.get('n'))).toEqual([1, 2, 3]);
            const last = await query.limitToLast(2).get().then(firestoreData);
            expect(last.docs.map((doc) => doc.get('n'))).toEqual([2, 3]);
            const aggregate = await collection
                .aggregate({
                    count: AggregateField.count(),
                    sum: AggregateField.sum('n'),
                    avg: AggregateField.average('n')
                })
                .get()
                .then(firestoreData);
            expect(aggregate.data()).toEqual({ count: 3, sum: 6, avg: 2 });
            const reader = query.stream().getReader();
            const streamed: unknown[] = [];
            try {
                for (;;) {
                    const item = await reader.read();
                    if (item.done) break;
                    streamed.push(item.value.get('n'));
                }
            } finally {
                reader.releaseLock();
            }
            expect(streamed).toEqual([1, 2, 3]);
            const explanation = await query
                .explain({ analyze: true })
                .then(firestoreData);
            expect(explanation.snapshot?.size).toBe(3);
            expect(explanation.metrics.executionStats?.resultsReturned).toBe(3);
            const plan = await query.explain().then(firestoreData);
            expect(plan.snapshot).toBeNull();
            expect(plan.metrics.planSummary).toBeDefined();
        });

        it('commits transactions and executes read-only document, query and aggregate reads', async () => {
            const collection = db!.collection(`${rootPath}/transactions`);
            const ref = collection.doc('counter');
            await ref.set({ n: 1 }).then(firestoreData);
            await db!
                .runTransaction(async (transaction) => {
                    const snapshot = await transaction
                        .get(ref)
                        .then(firestoreData);
                    transaction.update(ref, {
                        n: Number(snapshot.get('n')) + 1
                    });
                })
                .then(firestoreData);
            await db!
                .runTransaction(
                    async (transaction) => {
                        const documents = await transaction
                            .getAll(ref)
                            .then(firestoreData);
                        const query = await transaction
                            .get(collection)
                            .then(firestoreData);
                        const aggregate = await transaction
                            .get(collection.count())
                            .then(firestoreData);
                        expect(documents[0]!.get('n')).toBe(2);
                        expect(query.size).toBe(1);
                        expect(aggregate.data()).toEqual({ count: 1 });
                    },
                    { readOnly: true }
                )
                .then(firestoreData);
        });

        it('packs bulk writes and preserves independent failure results', async () => {
            const collection = db!.collection(`${rootPath}/bulk`);
            const existing = collection.doc('existing');
            await existing.create({ n: 0 }).then(firestoreData);
            const start = requests.length;
            const writer = db!.bulkWriter({ throttling: false });
            const pending = Array.from({ length: 25 }, (_, n) =>
                writer.set(collection.doc(String(n)), { n }).then(firestoreData)
            );
            pending.push(writer.create(existing, { n: 1 }).then(firestoreData));
            const settled = Promise.allSettled(pending);
            await writer.close().then(firestoreData);
            const outcomes = await settled;
            expect(
                outcomes.filter((outcome) => outcome.status === 'fulfilled')
            ).toHaveLength(25);
            expect(outcomes[25]).toMatchObject({
                status: 'rejected',
                reason: { code: 6 }
            });
            expect(
                requests
                    .slice(start)
                    .filter((url) => url.endsWith(':batchWrite'))
            ).toHaveLength(2);
            const count = await collection.count().get().then(firestoreData);
            expect(count.data().count).toBe(26);
        });

        it('builds correctly framed bundles from live snapshots', async () => {
            const ref = db!.doc(`${rootPath}/bundles/value`);
            await ref.set({ label: 'é😀' }).then(firestoreData);
            const snapshot = await ref.get().then(firestoreData);
            const query = await ref.parent.get().then(firestoreData);
            const bytes = db!
                .bundle(`live-${runId}`)
                .add(snapshot)
                .add('live-query', query)
                .build();
            const elements: Record<string, any>[] = [];
            let offset = 0;
            let metadataSize = 0;
            while (offset < bytes.length) {
                let digits = '';
                while (offset < bytes.length && bytes[offset] !== 123)
                    digits += String.fromCharCode(bytes[offset++]!);
                expect(digits).toMatch(/^\d+$/);
                const size = Number(digits);
                expect(size).toBeGreaterThan(0);
                expect(offset + size).toBeLessThanOrEqual(bytes.length);
                elements.push(
                    JSON.parse(
                        new TextDecoder('utf-8', { fatal: true }).decode(
                            bytes.slice(offset, offset + size)
                        )
                    )
                );
                offset += size;
                if (elements.length === 1) metadataSize = offset;
            }
            expect(elements[0]!.metadata.totalBytes).toBe(
                bytes.length - metadataSize
            );
            expect(elements[0]!.metadata.totalDocuments).toBe(1);
            expect(
                elements.find((element) => element.document)?.document.fields
                    .label.stringValue
            ).toBe('é😀');
            expect(
                elements.find((element) => element.namedQuery)?.namedQuery.name
            ).toBe('live-query');
            expect(
                elements.find((element) => element.documentMetadata)
                    ?.documentMetadata.queries
            ).toContain('live-query');
        });

        it('round-trips vector fields', async () => {
            const ref = db!.doc(`${rootPath}/fae_live_vectors/a`);
            await ref
                .set({ embedding: FieldValue.vector([1, 0, 0]) })
                .then(firestoreData);
            const snapshot = await ref.get().then(firestoreData);
            expect(snapshot.get('embedding')).toBeInstanceOf(VectorValue);
            expect(
                (snapshot.get('embedding') as VectorValue).toArray()
            ).toEqual([1, 0, 0]);
        });

        it.skipIf(process.env.FIRESTORE_LIVE_VECTORS !== '1')(
            'searches vectors using a provisioned vector index',
            async () => {
                const collection = db!.collection(
                    `${rootPath}/fae_live_vectors`
                );
                await collection
                    .doc('nearest')
                    .set({ embedding: FieldValue.vector([0, 0, 0]) })
                    .then(firestoreData);
                const result = await collection
                    .findNearest('embedding', [0, 0, 0], {
                        limit: 1,
                        distanceMeasure: 'EUCLIDEAN'
                    })
                    .get()
                    .then(firestoreData);
                expect(result.docs[0]!.id).toBe('nearest');
            }
        );

        it('observes document and query changes through polling and unsubscribes', async () => {
            const ref = db!.doc(`${rootPath}/polling/value`);
            await ref.set({ n: 0 }).then(firestoreData);
            const documents: number[] = [];
            const queries: number[] = [];
            const errors: Error[] = [];
            const stopDoc = ref.onSnapshot(
                { pollIntervalMs: 200 },
                (snapshot) => {
                    documents.push(Number(snapshot.get('n')));
                },
                (error) => errors.push(error)
            );
            const stopQuery = ref.parent.onSnapshot(
                { pollIntervalMs: 200 },
                (snapshot) => {
                    queries.push(Number(snapshot.docs[0]?.get('n')));
                },
                (error) => errors.push(error)
            );
            try {
                await expect
                    .poll(() => documents.includes(0) && queries.includes(0), {
                        timeout: 15000,
                        interval: 100
                    })
                    .toBe(true);
                await ref.update({ n: 1 }).then(firestoreData);
                await expect
                    .poll(() => documents.includes(1) && queries.includes(1), {
                        timeout: 15000,
                        interval: 100
                    })
                    .toBe(true);
                expect(errors).toEqual([]);
            } finally {
                stopDoc();
                stopQuery();
            }
            const counts = [documents.length, queries.length];
            await ref.update({ n: 2 }).then(firestoreData);
            expect([documents.length, queries.length]).toEqual(counts);
        });
    }
);
