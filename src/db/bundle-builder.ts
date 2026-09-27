import { DocumentSnapshot } from './document-snapshot.js';
import { QuerySnapshot } from './query.js';
import { Timestamp } from './timestamp.js';
import { autoId } from './firestore-path.js';
import { FirebaseEdgeError } from '../auth/errors.js';
import { FirestoreErrorInfo } from './firestore-error-codes.js';
import type { FirestoreDocument } from './firestore-document.js';

/** Builds the length-prefixed UTF-8 bundle format accepted by the Firebase Web SDK. */
export class BundleBuilder {
    private readonly documents = new Map<
        string,
        { document?: FirestoreDocument; readTime: string; queries: Set<string> }
    >();
    private readonly queries = new Map<string, object>();
    private built = false;
    private readonly createTime = Timestamp.now().toString();
    constructor(private readonly name = autoId()) {
        if (typeof name !== 'string' || !name)
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Bundle name must be a non-empty string.'
            });
    }
    get bundleId(): string {
        return this.name;
    }
    add(snapshot: DocumentSnapshot<any>): this;
    add(queryName: string, snapshot: QuerySnapshot<any>): this;
    add(
        value: DocumentSnapshot<any> | string,
        snapshot?: QuerySnapshot<any>
    ): this {
        if (this.built)
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.FAILED_PRECONDITION,
                message: 'Bundle has already been built.'
            });
        if (value instanceof DocumentSnapshot && snapshot === undefined) {
            this.addDocument(value);
            return this;
        }
        if (
            typeof value !== 'string' ||
            !value ||
            !(snapshot instanceof QuerySnapshot)
        )
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message:
                    'Expected a document snapshot or a named query snapshot.'
            });
        if (this.queries.has(value))
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Bundle query names must be unique.'
            });
        this.queries.set(value, {
            namedQuery: {
                name: value,
                bundledQuery: snapshot.query._bundledQuery(),
                readTime: snapshot.readTime.toString()
            }
        });
        for (const document of snapshot.docs) this.addDocument(document, value);
        return this;
    }
    build(): Uint8Array<ArrayBuffer> {
        if (this.built)
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.FAILED_PRECONDITION,
                message: 'Bundle has already been built.'
            });
        this.built = true;
        const chunks = [...this.queries.values()].map(encodeElement);
        for (const [name, entry] of this.documents) {
            chunks.push(
                encodeElement({
                    documentMetadata: {
                        name,
                        readTime: entry.readTime,
                        exists: !!entry.document,
                        queries: [...entry.queries]
                    }
                })
            );
            if (entry.document)
                chunks.push(encodeElement({ document: entry.document }));
        }
        const totalBytes = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
        const metadata = encodeElement({
            metadata: {
                id: this.name,
                createTime: this.createTime,
                version: 1,
                totalDocuments: this.documents.size,
                totalBytes
            }
        });
        const result = new Uint8Array(metadata.length + totalBytes);
        result.set(metadata);
        let offset = metadata.length;
        for (const chunk of chunks) {
            result.set(chunk, offset);
            offset += chunk.length;
        }
        return result;
    }
    private addDocument(snapshot: DocumentSnapshot<any>, query?: string): void {
        const name = snapshot.ref.firestore._documentName(snapshot.ref.path);
        const existing = this.documents.get(name);
        const queries = existing?.queries ?? new Set<string>();
        if (query) queries.add(query);
        if (existing && existing.readTime > snapshot.readTime.toString())
            return;
        this.documents.set(name, {
            document: snapshot._bundleDocument(),
            readTime: snapshot.readTime.toString(),
            queries
        });
    }
}

function encodeElement(value: object): Uint8Array {
    const encoder = new TextEncoder();
    const json = JSON.stringify(value);
    const bytes = encoder.encode(json);
    return encoder.encode(`${bytes.length}${json}`);
}
