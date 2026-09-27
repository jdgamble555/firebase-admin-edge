import { expect, it, vi } from 'vitest';
import { Firestore, CollectionGroup, Query } from './firestore.js';
import type { ServiceAccount } from '../auth/firebase-types.js';
const db = new Firestore({ project_id: 'p' } as ServiceAccount);

it('creates a dedicated group and preserves converters in groups and partitions', async () => {
    const group = db.collectionGroup('posts');
    expect(group).toBeInstanceOf(CollectionGroup);
    expect(group).toBeInstanceOf(Query);
    const converter = {
        toFirestore: (text: string) => ({ text }),
        fromFirestore: () => 'text'
    };
    const converted = group.withConverter(converter);
    expect(converted).toBeInstanceOf(CollectionGroup);
    expect(converted.withConverter(null).converter).toBeNull();
    const request = vi
        .spyOn(db, '_partitionQuery')
        .mockResolvedValue(['posts/b', 'users/a/posts/c']);
    const partitions = [];
    for await (const partition of converted.getPartitions(3))
        partitions.push(partition);
    expect(request).toHaveBeenCalledWith('posts', 3);
    expect(partitions).toHaveLength(3);
    expect(partitions[0]!.startAt).toBeUndefined();
    expect(partitions[0]!.endBefore?.[0]!.path).toBe('posts/b');
    expect(partitions[1]!.startAt?.[0]!.path).toBe('posts/b');
    expect(partitions[2]!.endBefore).toBeUndefined();
    expect(partitions[1]!.toQuery().converter).toBe(converter);
    request.mockRestore();
});

it('returns a single unbounded partition without a request and validates counts', async () => {
    const request = vi.spyOn(db, '_partitionQuery');
    const group = db.collectionGroup('posts');
    const partitions = [];
    for await (const partition of group.getPartitions(1))
        partitions.push(partition);
    expect(partitions).toHaveLength(1);
    expect(request).not.toHaveBeenCalled();
    for (const count of [0, -1, 1.5, Infinity, NaN])
        await expect(group.getPartitions(count).next()).rejects.toThrow(
            'positive'
        );
    expect(() => new CollectionGroup(db, 'a/b', vi.fn())).toThrow(
        'collection ID'
    );
    expect(() => group.withConverter({} as never)).toThrow();
    request.mockRestore();
});
