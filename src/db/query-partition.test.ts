import { firestoreData } from './firestore-results.js';
import { expect, it, vi } from 'vitest';
import { Firestore } from './firestore.js';
import { QueryPartition } from './query-partition.js';
import { FieldPath } from './field-path.js';
import type { ServiceAccount } from '../auth/firebase-types.js';

it('turns inclusive starts and exclusive ends into disjoint queries without mutating the base', async () => {
    const db = new Firestore({ project_id: 'p' } as ServiceAccount);
    const execute = vi.spyOn(db, '_query').mockResolvedValue([]);
    const query = db.collectionGroup('posts').orderBy(FieldPath.documentId());
    const partition = new QueryPartition(query, 'posts/a', 'users/b/posts/c');
    await partition.toQuery().get().then(firestoreData);
    expect(execute).toHaveBeenLastCalledWith('posts', {
        allDescendants: true,
        orders: [{ field: '__name__', direction: 'asc' }],
        start: {
            before: true,
            values: [
                {
                    referenceValue:
                        'projects/p/databases/(default)/documents/posts/a'
                }
            ]
        },
        end: {
            before: true,
            values: [
                {
                    referenceValue:
                        'projects/p/databases/(default)/documents/users/b/posts/c'
                }
            ]
        }
    });
    expect(partition.startAt?.[0]!.path).toBe('posts/a');
    expect(partition.endBefore?.[0]!.path).toBe('users/b/posts/c');
    const unbounded = new QueryPartition(query);
    expect(unbounded.toQuery()).toBe(query);
    expect(unbounded.startAt).toBeUndefined();
    expect(unbounded.endBefore).toBeUndefined();
});
