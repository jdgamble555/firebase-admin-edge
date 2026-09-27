import { firestoreData } from './firestore-results.js';
import { ExplainStats } from './pipeline.js';
import { expect, it, vi } from 'vitest';
import { Firestore } from './firestore.js';
import { Pipeline, PipelineResult, field, constant } from './pipeline.js';
import { FieldPath } from './field-path.js';
import { Timestamp } from './timestamp.js';
import type { ServiceAccount } from '../auth/firebase-types.js';
const account = { project_id: 'p' } as ServiceAccount;

it('returns pipeline execution failures as results', async () => {
    const db = new Firestore(account);
    const failure = new Error('offline');
    vi.spyOn(db, '_executePipeline').mockRejectedValue(failure);
    const result = await db.pipeline().collection('users').execute();
    expect(result).toEqual({ error: failure, data: null });
});
it('constructs immutable pipeline sources and validates ownership', () => {
    const db = new Firestore(account);
    const source = db.pipeline();
    const pipeline = source.collection('users');
    expect(pipeline.limit(2)._request().pipeline.stages).toHaveLength(2);
    expect(pipeline._request().pipeline.stages).toEqual([
        {
            name: 'collection',
            args: [{ referenceValue: '/users' }],
            options: {}
        }
    ]);
    expect(source.collection(db.collection('users'))._request()).toEqual(
        pipeline._request()
    );
    expect(
        source.collectionGroup('users')._request().pipeline.stages[0]!.name
    ).toBe('collection_group');
    expect(source.database()._request().pipeline.stages[0]!.name).toBe(
        'database'
    );
    expect(
        source.documents('users/a', db.doc('users/b'))._request().pipeline
            .stages[0]!.args
    ).toHaveLength(2);
    expect(() => source.documents()).toThrow();
    expect(() =>
        source.documents(new Firestore(account).doc('users/a'))
    ).toThrow();
    expect(() =>
        source.collection(new Firestore(account).collection('users'))
    ).toThrow();
    expect(() => pipeline.limit(-1)).toThrow();
    expect(() => pipeline.offset(1.5)).toThrow();
    expect(() => pipeline.where(null as never)).toThrow();
    expect(() => pipeline.sort()).toThrow();
    expect(() => pipeline.rawStage('', [])).toThrow();
    expect(() => new Pipeline(db)._request()).toThrow();
    expect(() =>
        pipeline.union(new Firestore(account).pipeline().database())
    ).toThrow();
});
it('serializes supported stages, subqueries and raw extension stages', () => {
    const db = new Firestore(account);
    const base = db.pipeline().collection('users');
    const pipeline = base
        .where(field('age').greaterThan(18))
        .select('name')
        .addFields(constant(1).as('n'))
        .define(field('name').as('label'))
        .removeFields('old')
        .distinct('name')
        .aggregate(field('age').average().as('avg'))
        .sort(field('name').ascending())
        .offset(1)
        .limit(2)
        .replaceWith({ n: constant(1) })
        .union(base)
        .unnest(field('tags').as('tag'))
        .sample(1)
        .findNearest({
            field: 'embedding',
            vectorValue: [1],
            distanceMeasure: 'euclidean'
        })
        .search({ query: 'hello' })
        .update([constant(true).as('active')])
        .delete()
        .rawStage('custom', [
            base.toArrayExpression(),
            base.toScalarExpression()
        ]);
    expect(
        pipeline._request().pipeline.stages.map((stage) => stage.name)
    ).toEqual([
        'collection',
        'where',
        'select',
        'add_fields',
        'let',
        'remove_fields',
        'distinct',
        'aggregate',
        'sort',
        'offset',
        'limit',
        'replace_with',
        'union',
        'unnest',
        'sample',
        'find_nearest',
        'search',
        'update',
        'delete',
        'custom'
    ]);
    expect(pipeline._request({ rawOptions: { mode: 'test' } }).options).toEqual(
        { mode: { stringValue: 'test' } }
    );
});
it('executes and streams decoded results with projection-safe document metadata', async () => {
    const db = new Firestore(account);
    const request = vi.spyOn(db, '_executePipeline').mockResolvedValue({
        results: [{ fields: { n: { integerValue: '2' } } }],
        executionTime: '2026-01-01T00:00:00Z'
    });
    const pipeline = db.pipeline().collection('users');
    const snapshot = await pipeline.execute().then(firestoreData);
    expect(snapshot.pipeline).toBe(pipeline);
    expect(snapshot.executionTime).toBeInstanceOf(Timestamp);
    expect(snapshot.results[0]!.data()).toEqual({ n: 2 });
    expect(snapshot.results[0]!.ref).toBeUndefined();
    expect(snapshot.results[0]!.get('n')).toBe(2);
    expect(snapshot.results[0]!.get('missing')).toBeUndefined();
    const stream = vi
        .spyOn(db, '_streamPipeline')
        .mockImplementation(async function* () {
            yield { fields: { n: { integerValue: '2' } } };
        });
    const reader = pipeline.stream().getReader();
    const first = await reader.read();
    const end = await reader.read();
    expect(first.value!.data()).toEqual({ n: 2 });
    expect(end.done).toBe(true);
    const cancelled = pipeline.stream().getReader();
    await cancelled.cancel();
    request.mockRejectedValue(new Error('denied'));
    stream.mockImplementation(async function* () {
        throw new Error('denied');
    });
    const failed = pipeline.stream().getReader();
    await expect(failed.read()).rejects.toThrow('denied');
    await expect(pipeline.execute().then(firestoreData)).rejects.toThrow(
        'denied'
    );
    const document = {
        name: 'projects/p/databases/(default)/documents/users/a',
        fields: {
            nested: { mapValue: { fields: { v: { integerValue: '3' } } } }
        },
        createTime: '2026-01-01T00:00:00Z',
        updateTime: '2026-01-01T00:00:00Z'
    };
    const result = new PipelineResult(db, document);
    expect(result.id).toBe('a');
    expect(result.createTime).toBeInstanceOf(Timestamp);
    expect(result.updateTime).toBeInstanceOf(Timestamp);
    expect(result.get(new FieldPath('nested', 'v'))).toBe(3);
    expect(result.isEqual(new PipelineResult(db, document))).toBe(true);
    expect(result.isEqual(null)).toBe(false);
    document.fields.nested.mapValue.fields.v.integerValue = '4';
    expect(result.get('nested.v')).toBe(3);
});

it('decodes JSON explain statistics and preserves raw unsupported formats', () => {
    const stats = new ExplainStats({
        '@type': 'type.googleapis.com/google.protobuf.StringValue',
        value: '{"plan":"scan"}'
    });
    expect(stats.text).toBe('{"plan":"scan"}');
    expect(stats.json).toEqual({ plan: 'scan' });
    expect(stats.rawMessage).toHaveProperty('@type');
    expect(() => new ExplainStats({}).text).toThrow('Unsupported');
    expect(() => new ExplainStats({ value: 'plain text' }).json).toThrow();
    const db = new Firestore(account);
    expect(db.pipeline().collection('users')._hasWrites).toBe(false);
    expect(db.pipeline().collection('users').delete()._hasWrites).toBe(true);
});
