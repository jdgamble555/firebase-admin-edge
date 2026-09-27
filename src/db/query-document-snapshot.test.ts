import { expect, expectTypeOf, it } from 'vitest';
import { QueryDocumentSnapshot } from './query-document-snapshot.js';
import { DocumentSnapshot } from './document-snapshot.js';
import { Firestore } from './firestore.js';
import type { DocumentData, FirestoreDocument } from './firestore-document.js';
import type { ServiceAccount } from '../auth/firebase-types.js';

const ref = new Firestore({ project_id: 'p' } as ServiceAccount).doc('users/a');

it('extends DocumentSnapshot and guarantees existence and defined data', () => {
    const snapshot = new QueryDocumentSnapshot(ref, { name: 'users/a' });
    expect(snapshot).toBeInstanceOf(DocumentSnapshot);
    expect(snapshot.exists).toBe(true);
    expect(snapshot.id).toBe('a');
    expect(snapshot.ref).toBe(ref);
    expect(snapshot.data()).toEqual({});
    expectTypeOf(snapshot.exists).toEqualTypeOf<true>();
    expectTypeOf(snapshot.data()).toEqualTypeOf<DocumentData>();
});

it('uses the shared decoder and returns fresh data', () => {
    const snapshot = new QueryDocumentSnapshot(ref, {
        name: 'users/a',
        fields: { tags: { arrayValue: { values: [{ stringValue: 'admin' }] } } }
    });
    const data = snapshot.data();
    (data.tags as string[]).push('changed');
    expect(snapshot.data()).toEqual({ tags: ['admin'] });
});

it.each([undefined, null])('rejects a missing document (%s)', (document) => {
    expect(
        () =>
            new QueryDocumentSnapshot(
                ref,
                document as unknown as FirestoreDocument
            )
    ).toThrow('existing document');
});
