import { firestoreData } from './firestore-results.js';
import { FirebaseEdgeError } from '../auth/errors.js';
import { expect, it, vi } from 'vitest';
import { CollectionReference } from './collection-reference.js';
import { Query } from './query.js';
import { Firestore } from './firestore.js';
import type { ServiceAccount } from '../auth/firebase-types.js';

const firestore = new Firestore({ project_id: 'p' } as ServiceAccount);

it('returns add and list failures as results without claiming a document was created', async () => {
    const db = new Firestore({ project_id: 'p' } as ServiceAccount);
    const failure = new Error('denied');
    vi.spyOn(db, '_commit').mockRejectedValue(failure);
    vi.spyOn(db, '_listDocuments').mockRejectedValue(failure);
    const collection = db.collection('users');
    const added = await collection.add({});
    const listed = await collection.listDocuments();
    expect(added).toEqual({ error: failure, data: null });
    expect(listed).toEqual({ error: failure, data: null });
});

it('creates auto-ID references, adds documents and propagates write errors', async () => {
    const commit = vi.spyOn(firestore, '_commit').mockResolvedValue([]);
    const collection = firestore.collection('users');
    const generated = collection.doc();
    expect(generated.id).toMatch(/^[A-Za-z0-9]{20}$/);
    expect(commit).not.toHaveBeenCalled();
    const ref = await collection.add({ name: 'Alice' }).then(firestoreData);
    expect(ref.path).toMatch(/^users\/[A-Za-z0-9]{20}$/);
    expect(commit.mock.lastCall?.[0][0]).toMatchObject({
        kind: 'create',
        path: ref.path,
        fields: { name: { stringValue: 'Alice' } }
    });
    commit.mockRejectedValueOnce(new Error('denied'));
    await expect(collection.add({}).then(firestoreData)).rejects.toThrow(
        'denied'
    );
    commit.mockRestore();
});

it('preserves converters through doc, add, query chaining and listDocuments', async () => {
    const converter = {
        toFirestore: (value: { label: string }) => ({ name: value.label }),
        fromFirestore: () => ({ label: 'Alice' })
    };
    const collection = firestore.collection('users').withConverter(converter);
    expect(collection).toBeInstanceOf(CollectionReference);
    expect(collection.doc('a').converter).toBe(converter);
    expect(collection.doc('a').parent.converter).toBe(converter);
    expect(collection.where('name', '==', 'Alice').converter).toBe(converter);
    expect(collection.withConverter(null).converter).toBeNull();
    const list = vi
        .spyOn(firestore, '_listDocuments')
        .mockResolvedValue(['users/a', 'users/missing']);
    const refs = await collection.listDocuments().then(firestoreData);
    expect(refs.map((ref) => ref.path)).toEqual(['users/a', 'users/missing']);
    expect(refs.every((ref) => ref.converter === converter)).toBe(true);
    expect(list).toHaveBeenCalledWith('users');
    list.mockRestore();
});

it('is a Query with root collection metadata and document references', () => {
    const collection = new CollectionReference(firestore, 'users', vi.fn());
    expect(collection).toBeInstanceOf(Query);
    expect(collection.firestore).toBe(firestore);
    expect(collection).toMatchObject({
        id: 'users',
        path: 'users',
        parent: null
    });
    expect(collection.doc('a')).toMatchObject({ id: 'a', path: 'users/a' });
    expect(collection.doc('a/posts/p').path).toBe('users/a/posts/p');
    expect(collection.where('active', '==', true)).toBeInstanceOf(Query);
    expect(collection.where('active', '==', true)).not.toBeInstanceOf(
        CollectionReference
    );
});

it('exposes a parent document for nested collections and reads as an unfiltered query', async () => {
    const execute = vi.fn().mockResolvedValue([]);
    const collection = new CollectionReference(
        firestore,
        'users/a/posts',
        execute
    );
    expect(collection).toMatchObject({
        id: 'posts',
        parent: { id: 'a', path: 'users/a' }
    });
    const getResult = await collection.get().then(firestoreData);
    expect(getResult.empty).toBe(true);
    expect(execute).toHaveBeenCalledWith('users/a/posts', {});
});

it('rejects invalid collection paths and document IDs', () => {
    expect(
        () => new CollectionReference(firestore, 'users/a', vi.fn())
    ).toThrow(FirebaseEdgeError);
    const collection = new CollectionReference(firestore, 'users', vi.fn());
    for (const id of ['', '/', '..', 'a/b', 'a//b'])
        expect(() => collection.doc(id)).toThrow(FirebaseEdgeError);
});
it('compares collection references by query identity', () => {
    const db = new Firestore({ project_id: 'p' } as ServiceAccount);
    expect(db.collection('users').isEqual(db.collection('users'))).toBe(true);
    expect(db.collection('users').isEqual(db.collection('posts'))).toBe(false);
});
