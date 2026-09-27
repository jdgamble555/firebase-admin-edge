import type { Query } from './query.js';
import type { DocumentData } from './firestore-document.js';
import type { DocumentReference } from './document-reference.js';

export class QueryPartition<
    T = DocumentData,
    DbModelType extends DocumentData = DocumentData
> {
    /** @internal Obtain partitions from CollectionGroup.getPartitions(). */
    constructor(
        private readonly query: Query<T, DbModelType>,
        private readonly start?: string,
        private readonly end?: string
    ) {}
    get startAt(): DocumentReference[] | undefined {
        if (this.start === undefined) return undefined;
        return [this.query.firestore.doc(this.start)];
    }
    get endBefore(): DocumentReference[] | undefined {
        if (this.end === undefined) return undefined;
        return [this.query.firestore.doc(this.end)];
    }
    toQuery(): Query<T, DbModelType> {
        let query = this.query;
        const start = this.startAt;
        const end = this.endBefore;
        if (start) query = query.startAt(...start);
        if (end) query = query.endBefore(...end);
        return query;
    }
}
