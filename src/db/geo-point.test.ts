import { FirebaseEdgeError } from '../auth/errors.js';
import { expect, it } from 'vitest';
import { GeoPoint } from './geo-point.js';
it('validates coordinates and compares points', () => {
    const point = new GeoPoint(-90, 180);
    expect(point.toJSON()).toEqual({ latitude: -90, longitude: 180 });
    expect(point.isEqual(new GeoPoint(-90, 180))).toBe(true);
    expect(point.isEqual(new GeoPoint(0, 0))).toBe(false);
    expect(point.isEqual(null as never)).toBe(false);
    for (const value of [-91, 91, Infinity, NaN])
        expect(() => new GeoPoint(value, 0)).toThrow(FirebaseEdgeError);
    for (const value of [-181, 181, Infinity, NaN])
        expect(() => new GeoPoint(0, value)).toThrow(FirebaseEdgeError);
});
