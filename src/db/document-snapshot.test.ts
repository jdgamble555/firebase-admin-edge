import { firestoreData } from './firestore-results.js';
import { FirebaseEdgeError } from '../auth/errors.js';
import { expect, it } from 'vitest';
import { DocumentSnapshot } from './document-snapshot.js';
import { Firestore } from './firestore.js';
import type { ServiceAccount } from '../auth/firebase-types.js';
import { FieldPath } from './field-path.js';
import { QueryDocumentSnapshot } from './query-document-snapshot.js';

it('reads stored fields including nested and literal paths, without prototype leakage', () => {
    const snapshot = new DocumentSnapshot(ref, {
        name: ref.path,
        fields: {
            profile: {
                mapValue: { fields: { name: { stringValue: 'Alice' } } }
            },
            'a.b': { nullValue: null },
            tags: { arrayValue: { values: [{ integerValue: '1' }] } }
        }
    });
    expect(snapshot.get('profile.name')).toBe('Alice');
    expect(snapshot.get(new FieldPath('a.b'))).toBeNull();
    expect(snapshot.get('profile.missing')).toBeUndefined();
    expect(snapshot.get('profile.name.x')).toBeUndefined();
    expect(snapshot.get('toString')).toBeUndefined();
    expect(snapshot.get(new FieldPath('tags', '0'))).toBeUndefined();
    expect(() => snapshot.get('')).toThrow(FirebaseEdgeError);
    const missing = new DocumentSnapshot(ref, undefined);
    expect(missing.get('profile.name')).toBeUndefined();
});

it('calls converters only for existing data and keeps get(field) on stored values', () => {
    const converter = {
        toFirestore: (value: { label: string }) => ({ name: value.label }),
        fromFirestore: (raw: QueryDocumentSnapshot) => {
            expect(raw).toBeInstanceOf(QueryDocumentSnapshot);
            expect(raw.ref.converter).toBeNull();
            return { label: String(raw.data().name).toUpperCase() };
        }
    };
    const converted = ref.withConverter(converter);
    const snapshot = new DocumentSnapshot(converted, {
        name: ref.path,
        fields: { name: { stringValue: 'alice' } }
    });
    expect(snapshot.data()).toEqual({ label: 'ALICE' });
    expect(snapshot.get('name')).toBe('alice');
    expect(new DocumentSnapshot(converted, undefined).data()).toBeUndefined();
});

const ref = new Firestore({ project_id: 'p' } as ServiceAccount).doc('users/a');

it('represents a missing document with its reference and no data', () => {
    const snapshot = new DocumentSnapshot(ref, undefined);
    expect(snapshot.id).toBe('a');
    expect(snapshot.ref).toBe(ref);
    expect(snapshot.exists).toBe(false);
    expect(snapshot.data()).toBeUndefined();
});

it('distinguishes an existing empty document from a missing one', () => {
    const snapshot = new DocumentSnapshot(ref, { name: 'users/a' });
    expect(snapshot.exists).toBe(true);
    expect(snapshot.data()).toEqual({});
});

it('decodes a fresh copy of nested document fields on each call', () => {
    const snapshot = new DocumentSnapshot(ref, {
        name: 'users/a',
        fields: {
            profile: {
                mapValue: { fields: { name: { stringValue: 'Alice' } } }
            }
        }
    });
    const first = snapshot.data()!;
    (first.profile as { name: string }).name = 'Changed';
    expect(snapshot.data()).toEqual({ profile: { name: 'Alice' } });
    expect(snapshot.ref).toBe(ref);
});
it('exports raw bundle data without conversion or mutable aliases', () => {
    const db = new Firestore({ project_id: 'p' } as ServiceAccount);
    const ref = db.doc('users/a');
    const raw = {
        name: 'users/a',
        fields: { a: { integerValue: '1' } },
        readTime: '2023-11-14T22:13:20.123456789Z'
    };
    const snapshot = new DocumentSnapshot(ref, raw);
    expect(snapshot.readTime.toString()).toBe(raw.readTime);
    const document = snapshot._bundleDocument()!;
    expect(document.name).toBe(
        'projects/p/databases/(default)/documents/users/a'
    );
    expect(document.readTime).toBeUndefined();
    document.fields!.a = { integerValue: '2' };
    expect(snapshot.get('a')).toBe(1);
    expect(
        new DocumentSnapshot(ref, undefined)._bundleDocument()
    ).toBeUndefined();
});
it('exposes timestamp metadata and compares stored data without invoking converters', () => {
    const db = new Firestore({ project_id: 'p' } as ServiceAccount);
    const ref = db.doc('users/a');
    const document = {
        name: 'users/a',
        createTime: '2026-01-01T00:00:00.123456789Z',
        updateTime: '2026-01-02T00:00:00Z',
        fields: { a: { integerValue: '1' }, b: { booleanValue: true } }
    };
    const first = new DocumentSnapshot(ref, document);
    const second = new DocumentSnapshot(ref, {
        ...document,
        fields: { b: { booleanValue: true }, a: { integerValue: '1' } }
    });
    expect(first.createTime?.nanoseconds).toBe(123456789);
    expect(first.updateTime?.toString()).toBe('2026-01-02T00:00:00.000000000Z');
    expect(first.isEqual(second)).toBe(true);
    expect(first.isEqual(new DocumentSnapshot(ref, undefined))).toBe(false);
    expect(first.isEqual(null)).toBe(false);
    const missing = new DocumentSnapshot(ref, {
        name: 'users/a',
        missing: true,
        readTime: '2026-01-01T00:00:00Z'
    });
    expect(missing.exists).toBe(false);
    expect(missing.data()).toBeUndefined();
    expect(missing.createTime).toBeUndefined();
    expect(missing.updateTime).toBeUndefined();
    expect(missing.isEqual(new DocumentSnapshot(ref, undefined))).toBe(true);
});

it('decodes nested references and precision-preserving integers through snapshot reads', async () => {
    const db = new Firestore({ project_id: 'p' } as ServiceAccount);
    db.settings({ useBigInt: true });
    const snapshot = new DocumentSnapshot(db.doc('users/a'), {
        name: 'users/a',
        fields: {
            n: { integerValue: '9223372036854775807' },
            owner: {
                referenceValue:
                    'projects/p/databases/(default)/documents/users/b'
            },
            other: {
                referenceValue: 'projects/other/databases/db/documents/users/c'
            }
        }
    });
    expect(snapshot.data()?.n).toBe(9223372036854775807n);
    const owner = snapshot.get(
        'owner'
    ) as import('./document-reference.js').DocumentReference;
    expect(owner.path).toBe('users/b');
    expect(owner.firestore).toBe(db);
    const other = snapshot.get('other') as typeof owner;
    expect(other.firestore.projectId).toBe('other');
    expect(other.firestore.databaseId).toBe('db');
    expect(other.isEqual(snapshot.get('other') as typeof owner)).toBe(true);
    await db.terminate().then(firestoreData);
    expect(snapshot.get('owner')).toBeInstanceOf(owner.constructor);
});
