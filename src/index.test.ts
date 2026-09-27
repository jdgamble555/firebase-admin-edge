import { firestoreData } from './db/firestore-results.js';
import { expect, it, vi } from 'vitest';
import * as api from './index.js';
import { FirebaseEdgeError } from './auth/errors.js';

it('keeps service account tokens but removes manual provider code exchange', () => {
    expect(typeof api.getToken).toBe('function');
    expect(api).not.toHaveProperty('exchangeCodeForGoogleIdToken');
});

it('exports authentication configuration managers', () => {
    expect(typeof api.ProjectConfigManager).toBe('function');
    expect(typeof api.TenantManager).toBe('function');
});

it('exports the shared error class and Firestore error definitions', () => {
    expect(api.FirebaseEdgeError).toBe(FirebaseEdgeError);
    expect(api.FirestoreErrorInfo.INVALID_ARGUMENT.code).toBe(
        'firestore/invalid-argument'
    );
});

it('exports the complete requested class list as runtime constructors', () => {
    for (const name of [
        'AppCheck',
        'Storage',
        'Firestore',
        'VectorValue',
        'VectorQuery',
        'VectorQuerySnapshot',
        'BundleBuilder',
        'CollectionGroup',
        'QueryPartition',
        'Query',
        'CollectionReference',
        'DocumentReference',
        'DocumentSnapshot',
        'QueryDocumentSnapshot',
        'QuerySnapshot',
        'WriteBatch',
        'Transaction',
        'BulkWriter',
        'BulkWriterError',
        'Timestamp',
        'GeoPoint',
        'Bytes',
        'FieldPath',
        'FieldValue',
        'Filter',
        'AggregateField',
        'AggregateQuery',
        'AggregateQuerySnapshot'
    ] as const)
        expect(typeof api[name], name).toBe('function');
});
import {
    Firestore,
    Query,
    CollectionReference,
    DocumentReference,
    DocumentSnapshot,
    QueryDocumentSnapshot,
    QuerySnapshot
} from './index.js';
import { getDocument, runQuery } from './db/firestore-endpoints.js';
import type { ServiceAccount } from './auth/firebase-types.js';

vi.mock('./db/firestore-endpoints.js');

it('exports all six classes and returns their instances from public read APIs', async () => {
    const firestore = new Firestore(
        { project_id: 'p' } as ServiceAccount,
        undefined,
        undefined,
        {
            getCache: vi.fn().mockReturnValue({ access_token: 'token' }),
            setCache: vi.fn()
        }
    );
    const collection = firestore.collection('users');
    const ref = collection.doc('a');
    const document = {
        name: 'projects/p/databases/(default)/documents/users/a'
    };
    vi.mocked(getDocument)
        .mockResolvedValueOnce(document)
        .mockResolvedValueOnce(undefined);
    vi.mocked(runQuery)
        .mockResolvedValueOnce([document])
        .mockResolvedValueOnce([]);

    expect(collection).toBeInstanceOf(CollectionReference);
    expect(collection).toBeInstanceOf(Query);
    expect(collection.where('active', '==', true)).toBeInstanceOf(Query);
    expect(ref).toBeInstanceOf(DocumentReference);
    const found = await ref.get().then(firestoreData);
    const missing = await ref.get().then(firestoreData);
    expect(found).toBeInstanceOf(DocumentSnapshot);
    expect(found.ref).toBe(ref);
    expect(found.exists).toBe(true);
    expect(missing).toBeInstanceOf(DocumentSnapshot);
    expect(missing.exists).toBe(false);

    const results = await collection.get().then(firestoreData);
    expect(results).toBeInstanceOf(QuerySnapshot);
    expect(results.docs[0]).toBeInstanceOf(QueryDocumentSnapshot);
    expect(results.docs[0]).toBeInstanceOf(DocumentSnapshot);
    expect(results.docs[0]!.ref).toBeInstanceOf(DocumentReference);
    expect(results.docs[0]!.data()).toEqual({});
    const empty = await collection.get().then(firestoreData);
    expect(empty).toBeInstanceOf(QuerySnapshot);
    expect(empty.empty).toBe(true);
});
