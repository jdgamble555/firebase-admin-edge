import { expect, it, vi } from 'vitest';
import { Firestore } from './firestore.js';
import { BundleBuilder } from './bundle-builder.js';
import {
    DocumentSnapshot,
    QueryDocumentSnapshot
} from './document-snapshot.js';
import { QuerySnapshot } from './query.js';
import { Timestamp } from './timestamp.js';
import type { ServiceAccount } from '../auth/firebase-types.js';

const db = new Firestore({ project_id: 'p' } as ServiceAccount);
const time = new Timestamp(1700000000, 123456789);
const raw = {
    name: 'projects/p/databases/(default)/documents/users/a',
    fields: { name: { stringValue: 'é😀' } },
    createTime: time.toString(),
    updateTime: time.toString(),
    readTime: time.toString()
};

it('builds UTF-8 byte-framed bundles with metadata, raw document data, deduplication and named queries', () => {
    const converter = {
        toFirestore: () => ({}),
        fromFirestore: vi.fn(() => 'converted')
    };
    const doc = new QueryDocumentSnapshot(
        db.doc('users/a').withConverter(converter),
        raw
    );
    const query = db.collection('users').orderBy('name').limitToLast(2);
    const results = new QuerySnapshot(query, [doc as never], time);
    const builder = db
        .bundle('example')
        .add(doc)
        .add('users', results)
        .add('users-again', results);
    const bytes = builder.build();
    const elements: any[] = [];
    let offset = 0;
    let metadataBytes = 0;
    while (offset < bytes.length) {
        let digits = '';
        while (bytes[offset] !== 123)
            digits += String.fromCharCode(bytes[offset++]!);
        const size = Number(digits);
        elements.push(
            JSON.parse(
                new TextDecoder().decode(bytes.slice(offset, offset + size))
            )
        );
        offset += size;
        if (elements.length === 1) metadataBytes = offset;
    }
    expect(elements[0].metadata).toMatchObject({
        id: 'example',
        version: 1,
        totalDocuments: 1,
        totalBytes: bytes.length - metadataBytes
    });
    expect(elements[1].namedQuery).toMatchObject({
        name: 'users',
        readTime: time.toString(),
        bundledQuery: {
            parent: 'projects/p/databases/(default)/documents',
            limitType: 'LAST',
            structuredQuery: {
                orderBy: [
                    { field: { fieldPath: 'name' }, direction: 'ASCENDING' }
                ],
                limit: 2
            }
        }
    });
    expect(elements[3].documentMetadata).toMatchObject({
        exists: true,
        queries: ['users', 'users-again'],
        readTime: time.toString()
    });
    expect(elements[4].document).toEqual({
        name: raw.name,
        fields: raw.fields,
        createTime: raw.createTime,
        updateTime: raw.updateTime
    });
    expect(converter.fromFirestore).not.toHaveBeenCalled();
    expect(() => builder.build()).toThrow('already');
    expect(() => builder.add(doc)).toThrow('already');
});

it('supports empty bundles, missing documents and the latest snapshot of a repeated document', () => {
    const empty = new TextDecoder().decode(new BundleBuilder().build());
    expect(empty).toContain('"totalDocuments":0');
    const missing = new DocumentSnapshot(
        db.doc('users/a'),
        undefined,
        new Timestamp(time.seconds + 1, 0)
    );
    const old = new DocumentSnapshot(db.doc('users/a'), raw);
    const bytes = db.bundle('missing').add(missing).add(old).build();
    const json = new TextDecoder().decode(bytes);
    expect(json).toContain('"exists":false');
    expect(json).not.toContain('"document":');
});

it('rejects invalid names, inputs and duplicate query names', () => {
    expect(() => new BundleBuilder('')).toThrow('name');
    const builder = db.bundle('test');
    expect(() => builder.add({} as never)).toThrow('snapshot');
    expect(() =>
        builder.add('', new QuerySnapshot(db.collection('users'), []))
    ).toThrow('snapshot');
    builder.add('users', new QuerySnapshot(db.collection('users'), []));
    expect(() =>
        builder.add('users', new QuerySnapshot(db.collection('users'), []))
    ).toThrow('unique');
});

it('exposes stable explicit and generated bundle IDs', () => {
    expect(new BundleBuilder('test').bundleId).toBe('test');
    expect(new BundleBuilder().bundleId).toEqual(expect.any(String));
});
