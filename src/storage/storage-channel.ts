import type { Storage } from './storage.js';

/** A legacy object-change notification channel. */
export class Channel {
    constructor(
        readonly id: string,
        readonly resourceId: string,
        private readonly storage: Storage
    ) {}
    stop() {
        return this.storage.referenceAction(
            { kind: 'channel', id: this.id },
            { kind: 'stopChannel', id: this.id, resourceId: this.resourceId }
        );
    }
}
