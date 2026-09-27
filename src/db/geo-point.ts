import { FirestoreErrorInfo } from './firestore-error-codes.js';
import { FirebaseEdgeError } from '../auth/errors.js';
export class GeoPoint {
    constructor(
        readonly latitude: number,
        readonly longitude: number
    ) {
        if (!Number.isFinite(latitude) || latitude < -90 || latitude > 90)
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Invalid latitude.'
            });
        if (!Number.isFinite(longitude) || longitude < -180 || longitude > 180)
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Invalid longitude.'
            });
    }
    isEqual(other: GeoPoint): boolean {
        return (
            other instanceof GeoPoint &&
            this.latitude === other.latitude &&
            this.longitude === other.longitude
        );
    }
    toJSON(): { latitude: number; longitude: number } {
        return { latitude: this.latitude, longitude: this.longitude };
    }
}
