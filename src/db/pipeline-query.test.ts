import { expect, it } from 'vitest';
import { Firestore, Filter } from './firestore.js';
import type { ServiceAccount } from '../auth/firebase-types.js';
it('translates filters, ordering, cursors, limits and projection without network access', () => {
    const db = new Firestore({ project_id: 'p' } as ServiceAccount);
    const query = db
        .collection('books')
        .where(Filter.or(Filter.where('n', '>', 0), Filter.where('n', '==', 0)))
        .orderBy('n')
        .startAt(1)
        .endBefore(9)
        .offset(1)
        .limitToLast(2)
        .select('n');
    const pipeline = db.pipeline().createFrom(query);
    const stages = pipeline._request().pipeline.stages;
    expect(stages[0]!.name).toBe('collection');
    expect(stages.filter((stage) => stage.name === 'sort')).toHaveLength(2);
    expect(stages.at(-1)!.name).toBe('select');
    expect(JSON.stringify(stages)).toContain('greater_than_or_equal');
    expect(
        db.pipeline().createFrom(db.collectionGroup('books'))._request()
            .pipeline.stages[0]!.name
    ).toBe('collection_group');
    expect(() =>
        db
            .pipeline()
            .createFrom(
                new Firestore({ project_id: 'p' } as ServiceAccount).collection(
                    'books'
                )
            )
    ).toThrow('belong');
});
