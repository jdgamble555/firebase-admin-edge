import { FirebaseEdgeError } from '../auth/errors.js';
import { expect, it } from 'vitest';
import { validateConverter } from './firestore-converter.js';
it('accepts null or a complete converter and rejects incomplete converters', () => {
    expect(() => validateConverter(null)).not.toThrow();
    expect(() =>
        validateConverter({
            toFirestore: () => ({}),
            fromFirestore: () => ({})
        })
    ).not.toThrow();
    for (const value of [
        undefined,
        {},
        { toFirestore: () => ({}) },
        { fromFirestore: () => ({}) }
    ])
        expect(() => validateConverter(value as never)).toThrow(
            FirebaseEdgeError
        );
});
