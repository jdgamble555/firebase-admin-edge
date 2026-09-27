import { FirebaseEdgeError } from '../auth/errors.js';
import { expect, it } from 'vitest';
import { FieldPath, parseFieldPath } from './field-path.js';

it('parses canonical paths without losing escaped literal segments', () => {
    const path = new FieldPath('a.b', 'c`d', 'e\\f', 'normal');
    expect(parseFieldPath(path.toString())).toEqual([
        'a.b',
        'c`d',
        'e\\f',
        'normal'
    ]);
    for (const invalid of ['', 'a.', '.a', 'a..b', '`open', '`trailing\\'])
        expect(() => parseFieldPath(invalid)).toThrow(FirebaseEdgeError);
});
it('quotes literal segments, escapes backticks/backslashes and compares paths', () => {
    const path = new FieldPath('profile', 'first.name');
    expect(path.toString()).toBe('profile.`first.name`');
    expect(new FieldPath('a`b\\c').toString()).toBe('`a\\`b\\\\c`');
    expect(path.isEqual(new FieldPath('profile', 'first.name'))).toBe(true);
    expect(path.isEqual(new FieldPath('profile.first.name'))).toBe(false);
    expect(path.isEqual(null as never)).toBe(false);
    expect(FieldPath.documentId().toString()).toBe('__name__');
    expect(() => new FieldPath()).toThrow(FirebaseEdgeError);
    expect(() => new FieldPath('')).toThrow(FirebaseEdgeError);
    expect(() => new FieldPath(null as never)).toThrow(FirebaseEdgeError);
});
