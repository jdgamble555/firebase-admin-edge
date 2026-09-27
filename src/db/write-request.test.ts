import { WriteResult } from './write-request.js';
import { FirebaseEdgeError } from '../auth/errors.js';
import { expect, it } from 'vitest';
import { prepareWrite, normalizeUpdateArguments } from './write-request.js';
import { Firestore } from './firestore.js';
import { FieldValue } from './field-value.js';
import { FieldPath } from './field-path.js';
import { Timestamp } from './timestamp.js';
import type { ServiceAccount } from '../auth/firebase-types.js';
const ref = new Firestore({ project_id: 'p' } as ServiceAccount).doc('users/a');
it('encodes replacement, merge and dotted updates with preconditions', () => {
    expect(prepareWrite(ref, 'create', { n: 1 }).precondition).toEqual({
        exists: false
    });
    expect(prepareWrite(ref, 'set', { n: 1 }).mask).toBeUndefined();
    expect(
        prepareWrite(
            ref,
            'set',
            { profile: { name: 'A' }, empty: {} },
            { merge: true }
        ).mask
    ).toEqual(['profile.name', 'empty']);
    const update = prepareWrite(ref, 'update', {
        'profile.name': 'A',
        other: { n: 2 }
    });
    expect(update.mask).toEqual(['profile.name', 'other']);
    expect(update.fields?.profile).toEqual({
        mapValue: { fields: { name: { stringValue: 'A' } } }
    });
    expect(update.precondition).toEqual({ exists: true });
    expect(
        prepareWrite(ref, 'delete', undefined, undefined, {
            lastUpdateTime: new Timestamp(0, 1)
        }).precondition
    ).toEqual({ updateTime: '1970-01-01T00:00:00.000000001Z' });
});
it('encodes all transforms and deletion masks without storing sentinel objects', () => {
    const write = prepareWrite(ref, 'update', {
        old: FieldValue.delete(),
        time: FieldValue.serverTimestamp(),
        n: FieldValue.increment(2),
        tags: FieldValue.arrayUnion('a'),
        removed: FieldValue.arrayRemove('b')
    });
    expect(write.mask).toEqual(['old']);
    expect(write.fields).toEqual({});
    expect(write.transforms).toEqual([
        { fieldPath: 'time', setToServerValue: 'REQUEST_TIME' },
        { fieldPath: 'n', increment: { integerValue: '2' } },
        {
            fieldPath: 'tags',
            appendMissingElements: { values: [{ stringValue: 'a' }] }
        },
        {
            fieldPath: 'removed',
            removeAllFromArray: { values: [{ stringValue: 'b' }] }
        }
    ]);
    const selected = prepareWrite(
        ref,
        'set',
        {
            'a.b': 1,
            n: FieldValue.increment(1),
            ignored: FieldValue.serverTimestamp()
        },
        { mergeFields: [new FieldPath('a.b'), 'n'] }
    );
    expect(selected.mask).toEqual(['`a.b`']);
    expect(selected.transforms).toHaveLength(1);
});
it('guards invalid and conflicting writes', () => {
    expect(
        prepareWrite(ref, 'update', { n: 1 }, undefined, {}).precondition
    ).toEqual({ exists: true });
    expect(() =>
        prepareWrite(ref, 'update', {
            x: FieldValue.delete(),
            'x.y': FieldValue.increment(1)
        })
    ).toThrow('Conflicting');
    const condition = { exists: true };
    const captured = prepareWrite(
        ref,
        'delete',
        undefined,
        undefined,
        condition
    );
    condition.exists = false;
    expect(captured.precondition).toEqual({ exists: true });
    const cycle: Record<string, unknown> = {};
    cycle.self = cycle;
    for (const data of [null, [], { x: undefined }, { x: cycle }, { '': 1 }])
        expect(() => prepareWrite(ref, 'set', data as never)).toThrow(
            FirebaseEdgeError
        );
    expect(() => prepareWrite(ref, 'update', {})).toThrow(FirebaseEdgeError);
    expect(() => prepareWrite(ref, 'update', { x: 1, 'x.y': 2 })).toThrow(
        FirebaseEdgeError
    );
    expect(() => prepareWrite(ref, 'update', { 'x.y': 2, x: 1 })).toThrow(
        FirebaseEdgeError
    );
    expect(() => prepareWrite(ref, 'set', { x: FieldValue.delete() })).toThrow(
        FirebaseEdgeError
    );
    expect(() =>
        prepareWrite(ref, 'set', { x: [FieldValue.serverTimestamp()] })
    ).toThrow(FirebaseEdgeError);
    expect(() =>
        prepareWrite(ref, 'set', { x: 1 }, { merge: true, mergeFields: ['x'] })
    ).toThrow(FirebaseEdgeError);
    expect(() =>
        prepareWrite(ref, 'set', { x: 1 }, { merge: 'yes' as never })
    ).toThrow(FirebaseEdgeError);
    expect(() =>
        prepareWrite(ref, 'set', { x: 1 }, { mergeFields: ['missing'] })
    ).toThrow(FirebaseEdgeError);
    for (const condition of [
        { exists: 'yes' },
        { lastUpdateTime: 'bad' },
        { exists: true, lastUpdateTime: new Timestamp(0, 0) }
    ])
        expect(() =>
            prepareWrite(
                ref,
                'delete',
                undefined,
                undefined,
                condition as never
            )
        ).toThrow(FirebaseEdgeError);
});
it('ignores undefined map properties only when configured, without masking them for deletion', () => {
    const db = new Firestore({ project_id: 'p' } as ServiceAccount);
    db.settings({ ignoreUndefinedProperties: true });
    const write = prepareWrite(
        db.doc('users/a'),
        'set',
        { omitted: undefined, nested: { omitted: undefined, present: 1 } },
        { merge: true }
    );
    expect(write.fields).toEqual({
        nested: { mapValue: { fields: { present: { integerValue: '1' } } } }
    });
    expect(write.mask).toEqual(['nested.present']);
    const arrayWrite = prepareWrite(db.doc('users/a'), 'set', {
        items: [{ missing: undefined, present: 1 }]
    });
    expect(arrayWrite.fields).toEqual({
        items: {
            arrayValue: {
                values: [
                    { mapValue: { fields: { present: { integerValue: '1' } } } }
                ]
            }
        }
    });
    expect(() =>
        prepareWrite(db.doc('users/a'), 'set', { items: [undefined] })
    ).toThrow();
    const strict = new Firestore({ project_id: 'p' } as ServiceAccount);
    expect(() =>
        prepareWrite(strict.doc('users/a'), 'set', { omitted: undefined })
    ).toThrow();
});
it('normalizes variadic fields, literal FieldPaths, transforms and final preconditions', () => {
    const normalized = normalizeUpdateArguments(new FieldPath('a.b'), [
        1,
        'nested.count',
        FieldValue.increment(2),
        { lastUpdateTime: new Timestamp(1, 0) }
    ]);
    const write = prepareWrite(
        ref,
        'update',
        normalized.data,
        undefined,
        normalized.precondition
    );
    expect(write.fields).toEqual({ 'a.b': { integerValue: '1' } });
    expect(write.mask).toEqual(['`a.b`']);
    expect(write.transforms).toEqual([
        { fieldPath: 'nested.count', increment: { integerValue: '2' } }
    ]);
    expect(write.precondition).toEqual({
        updateTime: '1970-01-01T00:00:01.000000000Z'
    });
    expect(normalizeUpdateArguments({ n: 1 }, [{ exists: true }])).toEqual({
        data: { n: 1 },
        precondition: { exists: true }
    });
    for (const args of [
        [],
        [1, 'other'],
        [1, 'a', 2],
        [1, { invalid: true }],
        [1, 3, 4]
    ])
        expect(() => normalizeUpdateArguments('a', args)).toThrow();
    expect(() => normalizeUpdateArguments({}, [{}, {}])).toThrow();
    for (const condition of [null, false, { invalid: true }])
        expect(() =>
            prepareWrite(ref, 'update', { n: 1 }, undefined, condition as never)
        ).toThrow('precondition');
});

it('compares runtime write results by timestamp and validates construction', () => {
    const result = new WriteResult(new Timestamp(0, 1));
    expect(result.isEqual(new WriteResult(new Timestamp(0, 1)))).toBe(true);
    expect(result.isEqual(new WriteResult(new Timestamp(0, 2)))).toBe(false);
    expect(result.isEqual(null)).toBe(false);
    expect(() => new WriteResult(null as never)).toThrow(FirebaseEdgeError);
});
it('serializes minimum and maximum as transforms, including NaN', () => {
    const write = prepareWrite(ref, 'update', {
        low: FieldValue.minimum(-2),
        high: FieldValue.maximum(NaN)
    });
    expect(write.transforms).toEqual([
        { fieldPath: 'low', minimum: { integerValue: '-2' } },
        { fieldPath: 'high', maximum: { doubleValue: 'NaN' } }
    ]);
});
