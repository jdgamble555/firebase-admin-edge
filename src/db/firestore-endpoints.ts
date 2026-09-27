import { traceFirestoreOperation } from './firestore-telemetry.js';
import type { FirestoreOpenTelemetryOptions } from './firestore-settings.js';
import { logFirestore } from './firestore-logging.js';
import { FirestoreErrorInfo } from './firestore-error-codes.js';
import { restFetch } from '../rest-fetch.js';
import { FirebaseEdgeError, ensureError } from '../auth/errors.js';
import type { FirestoreDocument } from './firestore-document.js';
import { buildStructuredQuery, type QueryOptions } from './query-request.js';
import { type WriteOperation, WriteResult } from './write-request.js';
import type { AggregateSpec, AggregateData } from './aggregate.js';
import { aggregateReadTime, aggregateMetrics } from './aggregate.js';
import { decodeFields } from './firestore-document.js';
import { Timestamp } from './timestamp.js';
import { readJsonArray } from './json-stream.js';
import {
    parseExplainMetrics,
    type ExplainOptions,
    type ExplainMetrics
} from './explain.js';

export async function batchGetDocuments(
    projectId: string,
    databaseId: string,
    paths: string[],
    token: string,
    fetchFn?: typeof globalThis.fetch,
    fieldMask?: string[],
    transaction?: string
): Promise<(FirestoreDocument | undefined)[]> {
    const names = paths.map((path) =>
        createDocumentName(projectId, databaseId, path)
    );
    const requestedNames = new Set(names);
    const rows = await firestorePost<
        Array<{
            found?: FirestoreDocument;
            missing?: string;
            error?: FirestoreRestError['error'];
        }>
    >(
        projectId,
        databaseId,
        '',
        'batchGet',
        {
            documents: [...requestedNames],
            ...(transaction ? { transaction } : {}),
            ...(fieldMask ? { mask: { fieldPaths: fieldMask } } : {})
        },
        token,
        fetchFn
    );
    if (!Array.isArray(rows))
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_RESPONSE,
            message: 'Invalid batchGet response.'
        });
    const documents = new Map<string, FirestoreDocument | undefined>();
    const readTimes = new Map<string, Timestamp>();
    for (const row of rows) {
        if (row?.error) throw mapFirestoreError(row);
        const name = row?.found?.name ?? row?.missing;
        if (!name || !requestedNames.has(name))
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_RESPONSE,
                message: 'Unexpected batchGet document.'
            });
        const readTime = (row as { readTime?: string }).readTime;
        if (readTime) readTimes.set(name, Timestamp.fromString(readTime));
        documents.set(
            name,
            row.found && readTime ? { ...row.found, readTime } : row.found
        );
    }
    if (names.some((name) => !documents.has(name)))
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_RESPONSE,
            message: 'Incomplete batchGet response.'
        });
    const ordered = names.map((name) => documents.get(name));
    Object.defineProperty(ordered, 'readTimes', {
        value: names.map((name) => readTimes.get(name))
    });
    return ordered;
}

export async function listCollectionIds(
    projectId: string,
    databaseId: string,
    parent: string,
    token: string,
    fetchFn?: typeof globalThis.fetch
): Promise<string[]> {
    const ids: string[] = [];
    let pageToken: string | undefined;
    const seen = new Set<string>();
    do {
        const page = await firestorePost<{
            collectionIds?: string[];
            nextPageToken?: string;
        }>(
            projectId,
            databaseId,
            parent,
            'listCollectionIds',
            { pageSize: 1000, ...(pageToken ? { pageToken } : {}) },
            token,
            fetchFn
        );
        if (
            !page ||
            typeof page !== 'object' ||
            Array.isArray(page) ||
            (page.nextPageToken !== undefined &&
                typeof page.nextPageToken !== 'string') ||
            (page.collectionIds !== undefined &&
                (!Array.isArray(page.collectionIds) ||
                    page.collectionIds.some(
                        (id) =>
                            typeof id !== 'string' || !id || id.includes('/')
                    )))
        )
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_RESPONSE,
                message: 'Invalid collection list response.'
            });
        ids.push(...(page.collectionIds ?? []));
        pageToken = page.nextPageToken;
        if (pageToken && seen.has(pageToken))
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_RESPONSE,
                message: 'Repeated collection page token.'
            });
        if (pageToken) seen.add(pageToken);
    } while (pageToken);
    return ids;
}

export async function listDocumentPaths(
    projectId: string,
    databaseId: string,
    path: string,
    token: string,
    fetchFn?: typeof globalThis.fetch
): Promise<string[]> {
    const paths: string[] = [];
    let pageToken: string | undefined;
    const seen = new Set<string>();
    do {
        const { data, error } = await restFetch<
            { documents?: FirestoreDocument[]; nextPageToken?: string },
            FirestoreRestError
        >(createDocumentsURL(projectId, databaseId, path), {
            method: 'GET',
            bearerToken: token,
            global: { fetch: fetchFn },
            params: {
                pageSize: '1000',
                showMissing: 'true',
                ...(pageToken ? { pageToken } : {})
            }
        });
        if (error) throw mapFirestoreError(error);
        if (
            !data ||
            typeof data !== 'object' ||
            Array.isArray(data) ||
            (data.nextPageToken !== undefined &&
                typeof data.nextPageToken !== 'string') ||
            (data.documents !== undefined && !Array.isArray(data.documents))
        )
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_RESPONSE,
                message: 'Invalid document list response.'
            });
        const prefix = `${createDocumentName(projectId, databaseId, '')}/`;
        for (const document of data.documents ?? []) {
            if (
                typeof document?.name !== 'string' ||
                !document.name.startsWith(`${prefix}${path}/`) ||
                document.name.length === prefix.length + path.length + 1 ||
                document.name
                    .slice(prefix.length + path.length + 1)
                    .includes('/')
            )
                throw new FirebaseEdgeError({
                    ...FirestoreErrorInfo.INVALID_RESPONSE,
                    message: 'Invalid listed document name.'
                });
            paths.push(document.name.slice(prefix.length));
        }
        pageToken = data.nextPageToken;
        if (pageToken && seen.has(pageToken))
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_RESPONSE,
                message: 'Repeated document page token.'
            });
        if (pageToken) seen.add(pageToken);
    } while (pageToken);
    return paths;
}

export async function* streamQuery(
    projectId: string,
    databaseId: string,
    collectionPath: string,
    options: QueryOptions,
    token: string,
    fetchFn?: typeof globalThis.fetch,
    signal?: AbortSignal
): AsyncGenerator<FirestoreDocument> {
    for await (const row of streamQueryRows(
        projectId,
        databaseId,
        collectionPath,
        options,
        token,
        fetchFn,
        signal
    ))
        if (row.document) yield row.document;
}
export interface QueryRow {
    document?: FirestoreDocument;
    metrics?: ExplainMetrics;
    readTime?: string;
}
/** @internal Streaming transport shared by ordinary queries and query explain. */
export async function* streamQueryRows(
    projectId: string,
    databaseId: string,
    collectionPath: string,
    options: QueryOptions,
    token: string,
    fetchFn: typeof globalThis.fetch = globalThis.fetch,
    signal?: AbortSignal,
    explainOptions?: ExplainOptions
): AsyncGenerator<QueryRow> {
    const segments = collectionPath.split('/');
    const collectionId = segments.pop()!;
    const parent = segments.join('/');
    const response = await fetchFn(
        `${createDocumentsURL(projectId, databaseId, parent)}:runQuery`,
        {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${token}`,
                'Content-Type': 'application/json',
                Accept: 'application/json'
            },
            body: JSON.stringify({
                ...(explainOptions ? { explainOptions } : {}),
                structuredQuery: buildStructuredQuery(
                    collectionId,
                    options,
                    createDocumentName(projectId, databaseId, parent)
                )
            }),
            signal
        }
    );
    if (!response.ok) {
        const message = await response.text();
        let error: FirestoreRestError;
        try {
            error = JSON.parse(message) as FirestoreRestError;
        } catch {
            error = { error: { message } };
        }
        throw mapFirestoreError(error);
    }
    if (!response.body)
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_RESPONSE,
            message: 'Firestore returned no query stream.'
        });
    for await (const value of readJsonArray(response.body)) {
        const row = value as {
            document?: FirestoreDocument;
            error?: FirestoreRestError['error'];
            explainMetrics?: unknown;
            readTime?: string;
        };
        if (!row || typeof row !== 'object')
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_RESPONSE,
                message: 'Invalid query stream row.'
            });
        if (row.error) throw mapFirestoreError(row);
        if (!row.document) {
            if (row.explainMetrics)
                yield {
                    metrics: parseExplainMetrics(row.explainMetrics),
                    readTime: row.readTime
                };
            else if (row.readTime) yield { readTime: row.readTime };
            continue;
        }
        if (
            typeof row.document.name !== 'string' ||
            !row.document.name.startsWith(
                `${createDocumentName(projectId, databaseId, '')}/`
            )
        )
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_RESPONSE,
                message: 'Invalid query stream document.'
            });
        const readTime = (row as { readTime?: string }).readTime;
        yield {
            document: readTime ? { ...row.document, readTime } : row.document,
            readTime
        };
        if (row.explainMetrics)
            yield {
                metrics: parseExplainMetrics(row.explainMetrics),
                readTime: row.readTime
            };
    }
}

export function createDocumentName(
    projectId: string,
    databaseId: string,
    path: string
): string {
    return `projects/${projectId}/databases/${databaseId}/documents${path ? `/${path}` : ''}`;
}

function serializeWrites(
    projectId: string,
    databaseId: string,
    operations: WriteOperation[]
) {
    return operations.map((operation) => {
        const name = createDocumentName(projectId, databaseId, operation.path);
        return {
            ...(operation.kind === 'delete'
                ? { delete: name }
                : {
                      update: { name, fields: operation.fields },
                      ...(operation.mask
                          ? { updateMask: { fieldPaths: operation.mask } }
                          : {}),
                      ...(operation.transforms?.length
                          ? { updateTransforms: operation.transforms }
                          : {})
                  }),
            ...(operation.precondition
                ? { currentDocument: operation.precondition }
                : {})
        };
    });
}

/** @internal Independent REST writes, with one result or error per operation. */
export async function batchWrite(
    projectId: string,
    databaseId: string,
    operations: WriteOperation[],
    token: string,
    fetchFn?: typeof globalThis.fetch
): Promise<(WriteResult | FirebaseEdgeError)[]> {
    if (!operations.length) return [];
    if (
        new Set(operations.map((operation) => operation.path)).size !==
        operations.length
    )
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message: 'batchWrite requires distinct document paths.'
        });
    const writes = serializeWrites(projectId, databaseId, operations);
    // Leave headroom below the service request limit, including UTF-8 expansion.
    if (
        new TextEncoder().encode(JSON.stringify({ writes })).byteLength >
        9 * 1024 * 1024
    ) {
        if (operations.length === 1)
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_ARGUMENT,
                message: 'Write exceeds the bulk request size limit.'
            });
        const middle = Math.ceil(operations.length / 2);
        const outcomes: (WriteResult | FirebaseEdgeError)[] = [];
        for (const part of [
            operations.slice(0, middle),
            operations.slice(middle)
        ]) {
            try {
                const results = await batchWrite(
                    projectId,
                    databaseId,
                    part,
                    token,
                    fetchFn
                );
                outcomes.push(...results);
            } catch (error) {
                const failure =
                    error instanceof FirebaseEdgeError
                        ? error
                        : mapFirestoreError({
                              error: { message: ensureError(error).message }
                          });
                outcomes.push(...part.map(() => failure));
            }
        }
        return outcomes;
    }
    const response = await firestorePost<{
        writeResults?: { updateTime?: string }[];
        status?: { code?: number; message?: string }[];
    }>(projectId, databaseId, '', 'batchWrite', { writes }, token, fetchFn);
    if (
        !Array.isArray(response?.writeResults) ||
        !Array.isArray(response?.status) ||
        response.writeResults.length !== operations.length ||
        response.status.length !== operations.length
    )
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_RESPONSE,
            message: 'Invalid batchWrite response.'
        });
    return response.status.map((status, index) => {
        if (
            !status ||
            typeof status !== 'object' ||
            (status.code !== undefined &&
                (!Number.isInteger(status.code) ||
                    status.code < 0 ||
                    status.code > 16))
        )
            return new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_RESPONSE,
                message: 'Invalid batchWrite status.'
            });
        if (status.code) {
            const names = [
                'OK',
                'CANCELLED',
                'UNKNOWN',
                'INVALID_ARGUMENT',
                'DEADLINE_EXCEEDED',
                'NOT_FOUND',
                'ALREADY_EXISTS',
                'PERMISSION_DENIED',
                'RESOURCE_EXHAUSTED',
                'FAILED_PRECONDITION',
                'ABORTED',
                'OUT_OF_RANGE',
                'UNIMPLEMENTED',
                'INTERNAL',
                'UNAVAILABLE',
                'DATA_LOSS',
                'UNAUTHENTICATED'
            ];
            return mapFirestoreError({
                error: { status: names[status.code], message: status.message }
            });
        }
        const write = response.writeResults![index];
        if (
            !write ||
            typeof write !== 'object' ||
            (!write.updateTime && operations[index]!.kind !== 'delete')
        )
            return new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_RESPONSE,
                message: 'Invalid batchWrite result.'
            });
        try {
            // Match Admin BulkWriter's epoch sentinel for deletes, which lack updateTime.
            return new WriteResult(
                write.updateTime
                    ? Timestamp.fromString(write.updateTime)
                    : new Timestamp(0, 0)
            );
        } catch {
            return new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_RESPONSE,
                message: 'Invalid batchWrite timestamp.'
            });
        }
    });
}

export async function commitWrites(
    projectId: string,
    databaseId: string,
    operations: WriteOperation[],
    token: string,
    fetchFn?: typeof globalThis.fetch,
    transaction?: string
): Promise<WriteResult[]> {
    const writes = serializeWrites(projectId, databaseId, operations);
    const result = await firestorePost<{
        writeResults?: { updateTime?: string }[];
        commitTime?: string;
    }>(
        projectId,
        databaseId,
        '',
        'commit',
        { writes, ...(transaction ? { transaction } : {}) },
        token,
        fetchFn
    );
    if (
        !result ||
        !Array.isArray(result.writeResults) ||
        result.writeResults.length !== operations.length ||
        !result.commitTime
    ) {
        // The API may omit writeResults for a read-only transaction commit.
        if (!operations.length && result?.commitTime) return [];
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_RESPONSE,
            message: 'Firestore returned an invalid commit response.'
        });
    }
    return result.writeResults.map(
        (write) =>
            new WriteResult(
                Timestamp.fromString(write.updateTime ?? result.commitTime!)
            )
    );
}

export async function beginTransaction(
    projectId: string,
    databaseId: string,
    token: string,
    fetchFn?: typeof globalThis.fetch,
    options?: { readOnly: true; readTime?: Timestamp }
): Promise<string> {
    const result = await firestorePost<{ transaction?: string }>(
        projectId,
        databaseId,
        '',
        'beginTransaction',
        {
            options: options
                ? {
                      readOnly: {
                          ...(options.readTime
                              ? { readTime: options.readTime.toString() }
                              : {})
                      }
                  }
                : { readWrite: {} }
        },
        token,
        fetchFn
    );
    if (!result?.transaction)
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_RESPONSE,
            message: 'Firestore returned no transaction ID.'
        });
    return result.transaction;
}

export async function rollbackTransaction(
    projectId: string,
    databaseId: string,
    transaction: string,
    token: string,
    fetchFn?: typeof globalThis.fetch
): Promise<void> {
    await firestorePost(
        projectId,
        databaseId,
        '',
        'rollback',
        { transaction },
        token,
        fetchFn
    );
}

export async function runAggregate(
    projectId: string,
    databaseId: string,
    collectionPath: string,
    options: QueryOptions,
    spec: AggregateSpec,
    token: string,
    fetchFn?: typeof globalThis.fetch,
    transaction?: string,
    explainOptions?: ExplainOptions
): Promise<AggregateData> {
    const segments = collectionPath.split('/');
    const collectionId = segments.pop()!;
    const parent = segments.join('/');
    const entries = Object.entries(spec);
    const aggregations = entries.map(([, field], index) => ({
        alias: `agg_${index}`,
        ...(field.aggregateType === 'count'
            ? { count: {} }
            : {
                  [field.aggregateType === 'avg' ? 'avg' : 'sum']: {
                      field: { fieldPath: field.field }
                  }
              })
    }));
    const result = await firestorePost<
        Array<{
            result?: { aggregateFields?: Parameters<typeof decodeFields>[0] };
            error?: FirestoreRestError['error'];
        }>
    >(
        projectId,
        databaseId,
        parent,
        'runAggregationQuery',
        {
            structuredAggregationQuery: {
                structuredQuery: buildStructuredQuery(
                    collectionId,
                    options,
                    createDocumentName(projectId, databaseId, parent)
                ),
                aggregations
            },
            ...(transaction ? { transaction } : {}),
            ...(explainOptions ? { explainOptions } : {})
        },
        token,
        fetchFn
    );
    if (!Array.isArray(result))
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_RESPONSE,
            message: 'Invalid aggregate response.'
        });
    for (const row of result) {
        if (!row || typeof row !== 'object')
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_RESPONSE,
                message: 'Invalid aggregate response row.'
            });
        if (row.error) throw mapFirestoreError(row);
    }
    const metricsRow = result.find(
        (row) => (row as { explainMetrics?: unknown }).explainMetrics
    ) as { explainMetrics?: unknown } | undefined;
    const metrics = metricsRow
        ? parseExplainMetrics(metricsRow.explainMetrics)
        : undefined;
    const fields = result.find((row) => row?.result)?.result?.aggregateFields;
    if (!fields && explainOptions && !explainOptions.analyze && metrics) {
        const data = {};
        Object.defineProperty(data, aggregateMetrics, { value: metrics });
        return data;
    }
    if (!fields)
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_RESPONSE,
            message: 'No aggregate result returned.'
        });
    const decoded = decodeFields(fields);
    const values = Object.fromEntries(
        entries.map(([alias], index) => {
            const value = decoded[`agg_${index}`];
            if (value !== null && typeof value !== 'number')
                throw new FirebaseEdgeError({
                    ...FirestoreErrorInfo.INVALID_RESPONSE,
                    message: 'Invalid aggregate field returned.'
                });
            return [alias, value];
        })
    );
    const readTime = (
        result.find((row) => (row as { readTime?: string }).readTime) as
            | { readTime?: string }
            | undefined
    )?.readTime;
    if (readTime)
        Object.defineProperty(values, aggregateReadTime, {
            value: Timestamp.fromString(readTime)
        });
    if (metrics)
        Object.defineProperty(values, aggregateMetrics, { value: metrics });
    return values;
}

async function firestorePost<T>(
    projectId: string,
    databaseId: string,
    parent: string,
    method: string,
    body: object,
    token: string,
    fetchFn?: typeof globalThis.fetch
): Promise<T> {
    const { data, error } = await restFetch<T, FirestoreRestError>(
        `${createDocumentsURL(projectId, databaseId, parent)}:${method}`,
        {
            method: 'POST',
            body,
            bearerToken: token,
            global: { fetch: fetchFn }
        }
    );
    logFirestore(`Firestore REST ${method}: ${error ? 'error' : 'success'}`);
    if (error) throw mapFirestoreError(error);
    return data as T;
}

/** @internal Fetch and sort all split points; REST pages are not globally ordered. */
export async function partitionQuery(
    projectId: string,
    databaseId: string,
    collectionId: string,
    count: number,
    token: string,
    fetchFn?: typeof globalThis.fetch
): Promise<string[]> {
    const names = new Set<string>();
    const seen = new Set<string>();
    let pageToken: string | undefined;
    const prefix = `${createDocumentName(projectId, databaseId, '')}/`;
    do {
        const page = await firestorePost<{
            partitions?: { values?: { referenceValue?: string }[] }[];
            nextPageToken?: string;
        }>(
            projectId,
            databaseId,
            '',
            'partitionQuery',
            {
                structuredQuery: buildStructuredQuery(collectionId, {
                    allDescendants: true,
                    orders: [{ field: '__name__', direction: 'asc' }]
                }),
                partitionCount: String(count - 1),
                pageSize: 1000,
                ...(pageToken ? { pageToken } : {})
            },
            token,
            fetchFn
        );
        if (
            !page ||
            (page.partitions !== undefined &&
                !Array.isArray(page.partitions)) ||
            (page.nextPageToken !== undefined &&
                typeof page.nextPageToken !== 'string')
        )
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_RESPONSE,
                message: 'Invalid partition response.'
            });
        for (const cursor of page.partitions ?? []) {
            const name = cursor?.values?.[0]?.referenceValue;
            const path =
                typeof name === 'string' && name.startsWith(prefix)
                    ? name.slice(prefix.length)
                    : '';
            const segments = path.split('/');
            if (
                cursor?.values?.length !== 1 ||
                !path ||
                segments.length % 2 !== 0 ||
                segments.some(
                    (segment) => !segment || segment === '.' || segment === '..'
                ) ||
                segments.at(-2) !== collectionId
            )
                throw new FirebaseEdgeError({
                    ...FirestoreErrorInfo.INVALID_RESPONSE,
                    message: 'Invalid partition cursor.'
                });
            names.add(path);
        }
        pageToken = page.nextPageToken;
        if (pageToken && seen.has(pageToken))
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_RESPONSE,
                message: 'Repeated partition page token.'
            });
        if (pageToken) seen.add(pageToken);
    } while (pageToken);
    const encoder = new TextEncoder();
    return [...names]
        .map((path) => ({ path, bytes: encoder.encode(path) }))
        .sort((left, right) => {
            for (
                let index = 0;
                index < Math.min(left.bytes.length, right.bytes.length);
                index++
            ) {
                const difference = left.bytes[index]! - right.bytes[index]!;
                if (difference) return difference;
            }
            return left.bytes.length - right.bytes.length;
        })
        .map((entry) => entry.path);
}

/** @internal Configure the REST destination. */
export function configureFirestoreFetch(
    fetchFn: typeof globalThis.fetch,
    host: string,
    ssl = true,
    port?: number,
    telemetry?: FirestoreOpenTelemetryOptions
): typeof globalThis.fetch {
    if (
        typeof host !== 'string' ||
        !host ||
        /[\s/?#@]/.test(host) ||
        host.includes('://')
    )
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message: 'host must be a hostname with an optional port.'
        });
    const url = new URL(`${ssl ? 'https' : 'http'}://${host}`);
    if (port !== undefined) url.port = String(port);
    const origin = url.origin;
    return (input, init) => {
        const url = new URL(
            input instanceof Request ? input.url : String(input)
        );
        if (url.origin !== 'https://firestore.googleapis.com')
            return fetchFn(input, init);
        const destination = `${origin}${url.pathname}${url.search}`;
        return traceFirestoreOperation('firestore.rest', telemetry, () =>
            fetchFn(
                input instanceof Request
                    ? new Request(destination, input)
                    : destination,
                init
            )
        );
    };
}

type FirestoreRestError = { error?: { status?: string; message?: string } };

function createDocumentsURL(
    projectId: string,
    databaseId: string,
    path: string
): string {
    const parts = ['projects', projectId, 'databases', databaseId, 'documents'];
    if (path) parts.push(...path.split('/'));
    return `https://firestore.googleapis.com/v1/${parts.map(encodeURIComponent).join('/')}`;
}

function mapFirestoreError(error: FirestoreRestError): FirebaseEdgeError {
    const details = Array.isArray(error)
        ? error.find((row) => row?.error)?.error
        : error && typeof error === 'object'
          ? error.error
          : undefined;
    return new FirebaseEdgeError(
        {
            ...FirestoreErrorInfo.UNKNOWN,
            ...(typeof details?.status === 'string' && details.status
                ? {
                      code: `firestore/${details.status.toLowerCase().replaceAll('_', '-')}`
                  }
                : {}),
            message:
                typeof details?.message === 'string'
                    ? details.message
                    : FirestoreErrorInfo.UNKNOWN.message
        },
        { cause: ensureError(error) }
    );
}

export async function runQuery(
    projectId: string,
    databaseId: string,
    collectionPath: string,
    options: QueryOptions,
    token: string,
    fetchFn?: typeof globalThis.fetch,
    transaction?: string
): Promise<FirestoreDocument[]> {
    const segments = collectionPath.split('/');
    const collectionId = segments.pop()!;
    const data = await firestorePost<
        Array<{
            document?: FirestoreDocument;
            error?: { status?: string; message?: string };
        }>
    >(
        projectId,
        databaseId,
        segments.join('/'),
        'runQuery',
        {
            ...(transaction ? { transaction } : {}),
            structuredQuery: buildStructuredQuery(
                collectionId,
                options,
                createDocumentName(projectId, databaseId, segments.join('/'))
            )
        },
        token,
        fetchFn
    );
    if (!Array.isArray(data))
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_RESPONSE,
            message: 'Firestore returned an invalid query response.'
        });
    const documents: FirestoreDocument[] = [];
    for (const row of data) {
        if (!row || typeof row !== 'object')
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_RESPONSE,
                message: 'Firestore returned an invalid query row.'
            });
        if (row.error) throw mapFirestoreError(row);
        if (!row.document) continue;
        if (
            typeof row.document.name !== 'string' ||
            !row.document.name.startsWith(
                `projects/${projectId}/databases/${databaseId}/documents/`
            )
        )
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_RESPONSE,
                message: 'Firestore returned an invalid query document.'
            });
        const readTime = (row as { readTime?: string }).readTime;
        documents.push(readTime ? { ...row.document, readTime } : row.document);
    }
    const readTime = (data.at(-1) as { readTime?: string } | undefined)
        ?.readTime;
    if (readTime)
        Object.defineProperty(documents, 'readTime', { value: readTime });
    return documents;
}

/** Read via batchGet so found and missing documents both retain server read times. */
export async function getDocument(
    projectId: string,
    databaseId: string,
    path: string,
    token: string,
    fetchFn?: typeof globalThis.fetch,
    transaction?: string
): Promise<FirestoreDocument | undefined> {
    const documents = await batchGetDocuments(
        projectId,
        databaseId,
        [path],
        token,
        fetchFn,
        undefined,
        transaction
    );
    if (documents[0]) return documents[0];
    const readTime = (documents as { readTimes?: Timestamp[] }).readTimes?.[0];
    if (!readTime) return undefined;
    return {
        name: createDocumentName(projectId, databaseId, path),
        missing: true,
        readTime: readTime.toString()
    };
}

/** Execute REST pipeline stages, preserving errors from streamed response rows. */
export async function executePipeline(
    projectId: string,
    databaseId: string,
    structuredPipeline: object,
    token: string,
    fetchFn?: typeof globalThis.fetch,
    transaction?: string,
    readTime?: Timestamp
): Promise<import('./pipeline.js').PipelineResponse> {
    if (transaction && readTime)
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_ARGUMENT,
            message: 'Choose a transaction or readTime.'
        });
    const rows = await firestorePost<
        ({
            results?: Partial<FirestoreDocument>[];
            executionTime?: string;
            explainStats?: { data?: unknown };
        } & FirestoreRestError)[]
    >(
        projectId,
        databaseId,
        '',
        'executePipeline',
        {
            structuredPipeline,
            ...(transaction ? { transaction } : {}),
            ...(readTime ? { readTime: readTime.toString() } : {})
        },
        token,
        fetchFn
    );
    if (!Array.isArray(rows))
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_RESPONSE,
            message: 'Invalid pipeline response.'
        });
    const result: import('./pipeline.js').PipelineResponse = {
        results: [],
        executionTime: ''
    };
    for (const row of rows) {
        if (!row || typeof row !== 'object')
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_RESPONSE,
                message: 'Invalid pipeline row.'
            });
        if (row.error) throw mapFirestoreError(row);
        if (
            row.results !== undefined &&
            (!Array.isArray(row.results) ||
                row.results.some(
                    (document) =>
                        !document ||
                        typeof document !== 'object' ||
                        Array.isArray(document)
                ))
        )
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_RESPONSE,
                message: 'Invalid pipeline results.'
            });
        result.results.push(...(row.results ?? []));
        if (row.executionTime) result.executionTime = row.executionTime;
        if (row.explainStats) result.explainStats = row.explainStats;
    }
    if (!result.executionTime)
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_RESPONSE,
            message: 'Missing pipeline execution time.'
        });
    Timestamp.fromString(result.executionTime);
    return result;
}

/** @internal Stream pipeline document batches with fetch cancellation and bounded buffering. */
export async function* streamPipeline(
    projectId: string,
    databaseId: string,
    structuredPipeline: object,
    token: string,
    fetchFn: typeof globalThis.fetch = globalThis.fetch,
    signal?: AbortSignal,
    readTime?: Timestamp
): AsyncGenerator<Partial<FirestoreDocument>> {
    signal?.throwIfAborted();
    const response = await fetchFn(
        `${createDocumentsURL(projectId, databaseId, '')}:executePipeline`,
        {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${token}`,
                'Content-Type': 'application/json',
                Accept: 'application/json'
            },
            body: JSON.stringify({
                structuredPipeline,
                ...(readTime ? { readTime: readTime.toString() } : {})
            }),
            signal
        }
    );
    if (!response.ok) {
        const text = await response.text();
        let error: FirestoreRestError;
        try {
            error = JSON.parse(text);
        } catch {
            error = { error: { message: text } };
        }
        throw mapFirestoreError(error);
    }
    if (!response.body)
        throw new FirebaseEdgeError({
            ...FirestoreErrorInfo.INVALID_RESPONSE,
            message: 'Missing pipeline stream.'
        });
    for await (const value of readJsonArray(response.body)) {
        const row = value as {
            results?: Partial<FirestoreDocument>[];
        } & FirestoreRestError;
        if (!row || typeof row !== 'object')
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_RESPONSE,
                message: 'Invalid pipeline row.'
            });
        if (row.error) throw mapFirestoreError(row);
        if (
            row.results !== undefined &&
            (!Array.isArray(row.results) ||
                row.results.some(
                    (document) =>
                        !document ||
                        typeof document !== 'object' ||
                        Array.isArray(document)
                ))
        )
            throw new FirebaseEdgeError({
                ...FirestoreErrorInfo.INVALID_RESPONSE,
                message: 'Invalid pipeline results.'
            });
        for (const document of row.results ?? []) {
            signal?.throwIfAborted();
            yield document;
        }
    }
}
