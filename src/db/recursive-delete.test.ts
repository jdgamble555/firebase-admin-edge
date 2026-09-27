import { firestoreData } from './firestore-results.js';
import { WriteResult } from './write-request.js';
import { expect, it, vi } from 'vitest';
import { Firestore } from './firestore.js';
import { deleteRecursively } from './recursive-delete.js';
import { Timestamp } from './timestamp.js';
import type { ServiceAccount } from '../auth/firebase-types.js';

it('visits descendants of missing documents and drains deletions', async () => {
    const db = new Firestore({ project_id: 'p' } as ServiceAccount);
    vi.spyOn(db, '_listDocuments').mockImplementation(async (path) =>
        path === 'users' ? ['users/missing'] : ['users/missing/posts/one']
    );
    vi.spyOn(db, '_listCollections').mockImplementation(async (path) =>
        path === 'users/missing' ? [db.collection('users/missing/posts')] : []
    );
    const commit = vi
        .spyOn(db, '_batchWrite')
        .mockResolvedValue([new WriteResult(Timestamp.now())]);
    const writer = db.bulkWriter({ throttling: false });
    await deleteRecursively(db.collection('users'), writer);
    expect(commit.mock.calls.map((call) => call[0][0]!.path)).toEqual([
        'users/missing',
        'users/missing/posts/one'
    ]);
    await writer.close().then(firestoreData);
});

it('continues after failures and still deletes the root reference', async () => {
    const db = new Firestore({ project_id: 'p' } as ServiceAccount);
    vi.spyOn(db, '_listCollections').mockRejectedValue(
        new Error('list failed')
    );
    const writer = db.bulkWriter({ throttling: false });
    const remove = vi
        .spyOn(writer, 'delete')
        .mockRejectedValue(new Error('delete failed'));
    await expect(
        deleteRecursively(db.doc('users/a'), writer)
    ).rejects.toMatchObject({
        message:
            '2 recursive delete operation(s) failed. Last error: delete failed',
        cause: expect.any(Error)
    });
    expect(remove).toHaveBeenCalledOnce();
});
