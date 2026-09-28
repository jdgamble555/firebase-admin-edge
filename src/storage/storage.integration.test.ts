import { readFileSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Storage, calculateStorageCrc32c } from './storage.js';
import { StorageCrc32c } from './storage-checksum.js';
import { TokenCache } from '../utils/token-cache.js';
import type { ServiceAccount } from '../auth/firebase-types.js';
import { getToken } from '../auth/google-oauth.js';

describe.skipIf(process.env.STORAGE_SPECIAL_LIVE_TESTS !== '1')(
    'live specialized Storage resources in a temporary bucket',
    () => {
        const bucketName = `fae-storage-extra-${crypto.randomUUID()}`;
        const topicId = `fae-storage-${crypto.randomUUID()}`;
        let storage: Storage;
        let account: ServiceAccount;
        let accessToken: string;
        let created = false;
        let topicCreated = false;
        let notificationId: string | undefined;
        let hmacAccessId: string | undefined;

        // Fixture setup also needs Pub/Sub topic administration and the Storage service agent.
        async function fixtureRequest(
            url: string,
            method: string,
            body?: object
        ): Promise<Record<string, any>> {
            const response = await fetch(url, {
                method,
                headers: {
                    Authorization: `Bearer ${accessToken}`,
                    'Content-Type': 'application/json'
                },
                ...(body !== undefined && { body: JSON.stringify(body) }),
                signal: AbortSignal.timeout(30000)
            });
            const text = await response.text();
            if (!response.ok) {
                throw new Error(
                    `Fixture ${method} failed (${response.status}): ${text}`
                );
            }
            return text ? JSON.parse(text) : {};
        }

        beforeAll(async () => {
            const raw =
                process.env.PRIVATE_FIREBASE_ADMIN_CONFIG ??
                (process.env.GOOGLE_APPLICATION_CREDENTIALS
                    ? readFileSync(
                          process.env.GOOGLE_APPLICATION_CREDENTIALS,
                          'utf8'
                      )
                    : '');
            account = JSON.parse(raw || '{}') as ServiceAccount;
            if (
                !account.client_email ||
                !account.private_key ||
                !account.project_id
            ) {
                throw new Error(
                    'Specialized live tests require service-account credentials.'
                );
            }
            const { error: tokenError, data: token } = await getToken(account);
            if (tokenError) {
                throw tokenError;
            }
            accessToken = token.access_token;
            const cache = new TokenCache();
            storage = new Storage(account, {
                bucketName,
                fetch: (input, init) =>
                    fetch(input, {
                        ...init,
                        signal: AbortSignal.timeout(30000)
                    }),
                cache: {
                    getCache: cache.get.bind(cache),
                    setCache: cache.set.bind(cache)
                }
            });
            const { error } = await storage.createBucket({
                location: process.env.STORAGE_TEST_LOCATION ?? 'US',
                softDeletePolicy: { retentionDurationSeconds: '0' },
                iamConfiguration: {
                    uniformBucketLevelAccess: { enabled: false },
                    publicAccessPrevention: 'enforced'
                }
            });
            if (error) {
                throw error;
            }
            created = true;
        }, 60000);

        afterAll(async () => {
            if (!created) {
                return;
            }
            if (
                storage.bucketName !== bucketName ||
                !bucketName.startsWith('fae-storage-extra-')
            ) {
                throw new Error(
                    'Refusing cleanup outside the specialized test bucket.'
                );
            }
            const failures: unknown[] = [];
            if (notificationId) {
                const { error } =
                    await storage.deleteNotification(notificationId);
                if (error) {
                    failures.push(error);
                }
            }
            if (topicCreated) {
                try {
                    await fixtureRequest(
                        `https://pubsub.googleapis.com/v1/projects/${account.project_id}/topics/${topicId}`,
                        'DELETE'
                    );
                } catch (cause) {
                    failures.push(cause);
                }
            }
            if (hmacAccessId) {
                const { error: inactiveError } = await storage.updateHmacKey(
                    hmacAccessId,
                    'INACTIVE'
                );
                const { error: deleteError } =
                    await storage.deleteHmacKey(hmacAccessId);
                if (inactiveError || deleteError) {
                    failures.push(inactiveError ?? deleteError);
                }
            }
            const { error: listError, data: page } = await storage.listFiles({
                versions: true
            });
            if (listError) {
                failures.push(listError);
            } else {
                const { error, data } = await storage.deleteFiles(
                    page.files.map(({ name, generation }) => ({
                        name,
                        generation
                    }))
                );
                if (error) {
                    failures.push(error);
                } else {
                    failures.push(
                        ...data.results.flatMap(({ error }) =>
                            error ? [error] : []
                        )
                    );
                }
            }
            const { error } = await storage.deleteBucket();
            if (error) {
                failures.push(error);
            }
            if (failures.length) {
                throw new AggregateError(
                    failures,
                    `Cleanup failed for ${bucketName}`
                );
            }
        }, 60000);

        it('creates, lists, reads, updates and deletes bucket, default-object and object ACLs', async () => {
            const { error: uploadError } = await storage.upload(
                'acl.txt',
                'acl test'
            );
            if (uploadError) {
                throw uploadError;
            }
            const { error: aclError, data: bucketAcl } = await storage.listAcl({
                scope: 'bucket'
            });
            if (aclError) {
                throw aclError;
            }
            const projectEntry = bucketAcl.items.find(({ entity }) =>
                /^project-(owners|editors|viewers)-\d+$/.test(entity)
            );
            if (!projectEntry) {
                throw new Error(
                    'Expected a project ACL entry on the disposable bucket.'
                );
            }
            // The uploading account owns objects and cannot be downgraded; use the test project's viewers group.
            const entity = projectEntry.entity.replace(
                /^project-(owners|editors|viewers)-/,
                'project-viewers-'
            );
            for (const target of [
                { scope: 'bucket' },
                { scope: 'defaultObject' },
                { scope: 'object', name: 'acl.txt' }
            ] as const) {
                const { error: createError } = await storage.createAcl(target, {
                    entity,
                    role: 'READER'
                });
                if (createError) {
                    throw createError;
                }
                const { error: listError, data: page } =
                    await storage.listAcl(target);
                if (listError) {
                    throw listError;
                }
                expect(
                    page.items.some((entry) => entry.entity === entity)
                ).toBe(true);
                const { error: readError, data: entry } = await storage.getAcl(
                    target,
                    entity
                );
                if (readError) {
                    throw readError;
                }
                expect(entry.role).toBe('READER');
                const { error: updateError } = await storage.updateAcl(target, {
                    entity,
                    role: 'OWNER'
                });
                if (updateError) {
                    throw updateError;
                }
                const { error } = await storage.deleteAcl(target, entity);
                if (error) {
                    throw error;
                }
            }
        }, 60000);

        it('creates, lists, reads, deactivates and deletes an HMAC key', async () => {
            const { error: createError, data: key } =
                await storage.createHmacKey(account.client_email);
            if (createError) {
                throw createError;
            }
            hmacAccessId = key.metadata.accessId;
            expect(typeof key.secret).toBe('string');
            const { error: listError, data: page } = await storage.listHmacKeys(
                { serviceAccountEmail: account.client_email }
            );
            if (listError) {
                throw listError;
            }
            expect(
                page.items.some((item) => item.accessId === hmacAccessId)
            ).toBe(true);
            const { error: readError, data: metadata } =
                await storage.getHmacKey(hmacAccessId);
            if (readError) {
                throw readError;
            }
            const { error: updateError, data: inactive } =
                await storage.updateHmacKey(
                    hmacAccessId,
                    'INACTIVE',
                    metadata.etag
                );
            if (updateError) {
                throw updateError;
            }
            expect(inactive.state).toBe('INACTIVE');
            const { error } = await storage.deleteHmacKey(hmacAccessId);
            if (error) {
                throw error;
            }
            hmacAccessId = undefined;
        }, 60000);

        it('creates, lists, reads and deletes notifications for an isolated Pub/Sub topic', async () => {
            const topicPath = `projects/${account.project_id}/topics/${topicId}`;
            await fixtureRequest(
                `https://pubsub.googleapis.com/v1/${topicPath}`,
                'PUT',
                {}
            );
            topicCreated = true;
            const agent = await fixtureRequest(
                `https://storage.googleapis.com/storage/v1/projects/${account.project_id}/serviceAccount`,
                'GET'
            );
            if (typeof agent.email_address !== 'string') {
                throw new Error('Missing Storage service-agent email.');
            }
            await fixtureRequest(
                `https://pubsub.googleapis.com/v1/${topicPath}:setIamPolicy`,
                'POST',
                {
                    policy: {
                        bindings: [
                            {
                                role: 'roles/pubsub.publisher',
                                members: [
                                    `serviceAccount:${agent.email_address}`
                                ]
                            }
                        ]
                    }
                }
            );
            const { error: createError, data: notification } =
                await storage.createNotification({
                    topic: `//pubsub.googleapis.com/${topicPath}`,
                    payload_format: 'JSON_API_V1',
                    event_types: ['OBJECT_FINALIZE'],
                    object_name_prefix: 'unused-notification-prefix/'
                });
            if (createError) {
                throw createError;
            }
            notificationId = notification.id;
            const { error: listError, data: page } =
                await storage.listNotifications();
            if (listError) {
                throw listError;
            }
            expect(page.items.some((item) => item.id === notification.id)).toBe(
                true
            );
            const { error: readError, data } = await storage.getNotification(
                notification.id
            );
            if (readError) {
                throw readError;
            }
            expect(data.topic).toBe(`//pubsub.googleapis.com/${topicPath}`);
            const { error } = await storage.deleteNotification(notification.id);
            if (error) {
                throw error;
            }
            notificationId = undefined;
        }, 60000);

        it.skipIf(process.env.STORAGE_LOCK_LIVE_TESTS !== '1')(
            'locks a one-second retention policy on the disposable test bucket',
            async () => {
                const { error: updateError, data: bucket } =
                    await storage.updateBucketMetadata({
                        retentionPolicy: { retentionPeriod: '1' }
                    });
                if (updateError) {
                    throw updateError;
                }
                const { error, data } = await storage.lockRetentionPolicy(
                    bucket.metageneration
                );
                if (error) {
                    throw error;
                }
                expect(data.retentionPolicy).toMatchObject({
                    isLocked: true,
                    retentionPeriod: '1'
                });
            },
            60000
        );
    }
);

describe.skipIf(process.env.STORAGE_LIVE_TESTS !== '1')(
    'live Storage REST integration',
    () => {
        const prefix = `firebase-admin-edge-tests/${crypto.randomUUID()}/`;
        let storage: Storage | undefined;
        let account: ServiceAccount;

        beforeAll(() => {
            const raw =
                process.env.PRIVATE_FIREBASE_ADMIN_CONFIG ??
                (process.env.GOOGLE_APPLICATION_CREDENTIALS
                    ? readFileSync(
                          process.env.GOOGLE_APPLICATION_CREDENTIALS,
                          'utf8'
                      )
                    : '');
            account = JSON.parse(raw || '{}') as ServiceAccount;
            const config = JSON.parse(
                process.env.PUBLIC_FIREBASE_CONFIG ?? '{}'
            );
            const bucket =
                process.env.STORAGE_TEST_BUCKET ?? config.storageBucket;
            if (!account.client_email || !account.private_key || !bucket) {
                throw new Error(
                    'Set service account credentials and STORAGE_TEST_BUCKET (or PUBLIC_FIREBASE_CONFIG.storageBucket) for live Storage tests.'
                );
            }
            const cache = new TokenCache();
            storage = new Storage(account, {
                bucketName: bucket,
                fetch: (input, init) =>
                    fetch(input, {
                        ...init,
                        signal: AbortSignal.timeout(30000)
                    }),
                cache: {
                    getCache: cache.get.bind(cache),
                    setCache: cache.set.bind(cache)
                }
            });
        });

        afterAll(async () => {
            if (!storage) {
                return;
            }
            let pageToken: string | undefined;
            const targets: Array<{ name: string; generation: string }> = [];
            do {
                const { error, data } = await storage.listFiles({
                    prefix,
                    versions: true,
                    pageToken
                });
                if (error) {
                    throw error;
                }
                for (const file of data.files) {
                    if (!file.name.startsWith(prefix)) {
                        throw new Error(
                            'Refusing cleanup outside the test prefix.'
                        );
                    }
                    targets.push({
                        name: file.name,
                        generation: file.generation
                    });
                }
                pageToken = data.nextPageToken;
            } while (pageToken);
            const { error, data } = await storage.deleteFiles(targets, {
                ignoreNotFound: true
            });
            if (error) {
                throw error;
            }
            for (const result of data.results) {
                const { error: deleteError } = result;
                if (deleteError) {
                    throw deleteError;
                }
            }
        });

        it('uploads, patches, streams ranges, reads versions, copies, moves and batches deletion', async () => {
            const name = `${prefix}basic.txt`;
            const { error: uploadError, data: uploaded } =
                await storage!.upload(name, 'abcdef', {
                    contentType: 'text/plain',
                    crc32c: 'auto',
                    ifGenerationMatch: '0'
                });
            if (uploadError) {
                throw uploadError;
            }
            const { error: patchError, data: patched } =
                await storage!.updateMetadata(
                    name,
                    {
                        cacheControl: 'private, max-age=60',
                        metadata: { suite: 'storage' }
                    },
                    { ifGenerationMatch: uploaded.generation }
                );
            if (patchError) {
                throw patchError;
            }
            expect(patched.metadata?.suite).toBe('storage');
            const { error: streamError, data: stream } =
                await storage!.downloadStream(name, {
                    start: 1,
                    end: 3,
                    generation: uploaded.generation
                });
            if (streamError) {
                throw streamError;
            }
            expect(stream.status).toBe(206);
            const text = await stream.text();
            expect(text).toBe('bcd');
            const { error: copyError } = await storage!.copy(
                name,
                `${prefix}copy.txt`,
                {
                    sourceGeneration: uploaded.generation,
                    ifGenerationMatch: '0'
                }
            );
            if (copyError) {
                throw copyError;
            }
            const { error: moveError } = await storage!.move(
                `${prefix}copy.txt`,
                `${prefix}moved.txt`,
                { ifGenerationMatch: '0' }
            );
            if (moveError) {
                throw moveError;
            }
            const { error: existsError, data: exists } = await storage!.exists(
                `${prefix}copy.txt`
            );
            if (existsError) {
                throw existsError;
            }
            expect(exists).toBe(false);
            const { error: deletedError, data: deleted } =
                await storage!.deleteFiles(
                    [`${prefix}moved.txt`, `${prefix}missing.txt`],
                    { ignoreNotFound: true }
                );
            if (deletedError) {
                throw deletedError;
            }
            expect(deleted.results.every(({ error }) => error === null)).toBe(
                true
            );
        });

        it('resumes a two-chunk upload, checks progress, and cancels another session', async () => {
            const bytes = new Uint8Array(262147).fill(65);
            const checksum = await calculateStorageCrc32c(bytes);
            const progressEvents: number[] = [];
            const { error: createError, data: session } =
                await storage!.createResumableUpload(`${prefix}resumable.bin`, {
                    size: bytes.length,
                    crc32c: checksum,
                    ifGenerationMatch: '0'
                });
            if (createError) {
                throw createError;
            }
            const { error: chunkError, data: partial } =
                await storage!.uploadChunk(session, bytes.slice(0, 262144), {
                    offset: 0,
                    totalSize: bytes.length,
                    onProgress: ({ bytesTransferred }) => {
                        progressEvents.push(bytesTransferred);
                    }
                });
            if (chunkError) {
                throw chunkError;
            }
            expect(partial).toEqual({ complete: false, nextOffset: 262144 });
            const { error: statusError, data: progress } =
                await storage!.getUploadStatus(session, bytes.length);
            if (statusError) {
                throw statusError;
            }
            expect(progress).toEqual(partial);
            const { error: finalError, data: final } =
                await storage!.uploadChunk(session, bytes.slice(262144), {
                    offset: 262144,
                    totalSize: bytes.length,
                    crc32c: checksum,
                    onProgress: ({ bytesTransferred }) => {
                        progressEvents.push(bytesTransferred);
                    }
                });
            if (finalError) {
                throw finalError;
            }
            expect(final.complete).toBe(true);
            expect(progressEvents).toEqual([262144, bytes.length]);
            const { error: downloadError, data: downloaded } =
                await storage!.download(`${prefix}resumable.bin`, {
                    verifyChecksum: true
                });
            if (downloadError) {
                throw downloadError;
            }
            expect(downloaded).toEqual(bytes);
            const { error: startError, data: unused } =
                await storage!.createResumableUpload(`${prefix}cancelled.bin`);
            if (startError) {
                throw startError;
            }
            const { error: cancelError } = await storage!.cancelUpload(unused);
            if (cancelError) {
                throw cancelError;
            }
        });

        it('rejects incorrect upload checksums at the server', async () => {
            const { error } = await storage!.upload(
                `${prefix}bad-checksum.txt`,
                'not empty',
                { crc32c: 'AAAAAA==', ifGenerationMatch: '0' }
            );
            expect(error).not.toBeNull();
            const { error: existsError, data: exists } = await storage!.exists(
                `${prefix}bad-checksum.txt`
            );
            if (existsError) {
                throw existsError;
            }
            expect(exists).toBe(false);
        });

        it('checks resumable checksums from session metadata and final responses', async () => {
            const { error: startError, data: session } =
                await storage!.createResumableUpload(
                    `${prefix}bad-session-crc`,
                    { size: 3, crc32c: 'AAAAAA==' }
                );
            if (startError) {
                throw startError;
            }
            const { error: chunkError } = await storage!.uploadChunk(
                session,
                'abc',
                { offset: 0, totalSize: 3 }
            );
            expect(chunkError).not.toBeNull();
            const { error: secondError, data: secondSession } =
                await storage!.createResumableUpload(`${prefix}bad-final-crc`, {
                    size: 3
                });
            if (secondError) {
                throw secondError;
            }
            const { error } = await storage!.uploadChunk(secondSession, 'abc', {
                offset: 0,
                totalSize: 3,
                crc32c: 'AAAAAA=='
            });
            expect(error).not.toBeNull();
        });

        it('automates chunking, resumes saved sessions, verifies streamed downloads and signs XML requests', async () => {
            const bytes = new Uint8Array(524291).fill(65);
            const name = `${prefix}automated.bin`;
            const { error: createError, data: session } =
                await storage!.createResumableUpload(name, {
                    size: bytes.length
                });
            if (createError) {
                throw createError;
            }
            const { error: chunkError } = await storage!.uploadChunk(
                session,
                bytes.slice(0, 262144),
                { offset: 0, totalSize: bytes.length }
            );
            if (chunkError) {
                throw chunkError;
            }
            const { error: uploadError } = await storage!.uploadStream(
                name,
                new Blob([bytes]).stream(),
                { sessionUri: session, size: bytes.length, chunkSize: 262144 }
            );
            if (uploadError) {
                throw uploadError;
            }
            const { error: streamError, data: stream } =
                await storage!.downloadStream(name, { verifyChecksum: true });
            if (streamError) {
                throw streamError;
            }
            const downloaded = await stream.arrayBuffer();
            expect(new Uint8Array(downloaded)).toEqual(bytes);
            const { error: signError, data: request } =
                await storage!.signXmlRequest({ method: 'GET', name });
            if (signError) {
                throw signError;
            }
            const response = await fetch(request, {
                signal: AbortSignal.timeout(30000)
            });
            expect(response.status).toBe(200);
            const signedBytes = await response.arrayBuffer();
            expect(new Uint8Array(signedBytes)).toEqual(bytes);
        });

        it('recovers a lost acknowledgement from a live chunk without duplicating bytes', async () => {
            let interrupted = false;
            const unstable = new Storage(account, {
                bucketName: storage!.bucketName,
                fetch: async (input, init) => {
                    const response = await fetch(input, {
                        ...init,
                        signal: AbortSignal.timeout(30000)
                    });
                    const range = new Headers(init?.headers).get(
                        'Content-Range'
                    );
                    if (
                        !interrupted &&
                        init?.method === 'PUT' &&
                        range?.startsWith('bytes 0-')
                    ) {
                        interrupted = true;
                        await response.body?.cancel();
                        throw new TypeError(
                            'Simulated lost chunk acknowledgement'
                        );
                    }
                    return response;
                }
            });
            const bytes = new Uint8Array(262147).fill(65);
            const { error, data } = await unstable.uploadStream(
                `${prefix}interrupted.bin`,
                bytes,
                { chunkSize: 262144 }
            );
            if (error) {
                throw error;
            }
            expect(interrupted).toBe(true);
            expect(data.size).toBe(String(bytes.length));
            const checksum = await calculateStorageCrc32c(bytes);
            expect(data.crc32c).toBe(checksum);
        });

        it('uses signed URLs for PUT and GET requests', async () => {
            const name = `${prefix}signed !.txt`;
            const { error: writeError, data: writeUrl } =
                await storage!.getSignedUrl(name, {
                    action: 'write',
                    contentType: 'text/plain',
                    expiresInSeconds: 300
                });
            if (writeError) {
                throw writeError;
            }
            const uploaded = await fetch(writeUrl, {
                method: 'PUT',
                headers: { 'Content-Type': 'text/plain' },
                body: 'signed',
                signal: AbortSignal.timeout(30000)
            });
            expect(uploaded.ok).toBe(true);
            await uploaded.body?.cancel();
            const { error: readError, data: readUrl } =
                await storage!.getSignedUrl(name, {
                    action: 'read',
                    expiresInSeconds: 300
                });
            if (readError) {
                throw readError;
            }
            const downloaded = await fetch(readUrl, {
                signal: AbortSignal.timeout(30000)
            });
            expect(downloaded.ok).toBe(true);
            const text = await downloaded.text();
            expect(text).toBe('signed');
        });

        it('uses Admin Bucket and File references with result errors, Web Streams, and Firebase download URLs', async () => {
            const bucket = storage!.bucket();
            const file = bucket.file(`${prefix}admin-reference`);
            const { error: saveError } = await file.save('reference bytes', {
                resumable: false,
                metadata: {
                    contentType: 'text/plain',
                    metadata: {
                        firebaseStorageDownloadTokens: crypto.randomUUID()
                    }
                },
                preconditionOpts: { ifGenerationMatch: 0 }
            });
            if (saveError) {
                throw saveError;
            }
            const { error: existsError, data: exists } = await file.exists();
            if (existsError) {
                throw existsError;
            }
            expect(exists).toBe(true);
            const { error: metadataError } = await file.setMetadata({
                cacheControl: 'private, max-age=0'
            });
            if (metadataError) {
                throw metadataError;
            }
            const { error: downloadError, data: bytes } = await file.download({
                validation: 'crc32c'
            });
            if (downloadError) {
                throw downloadError;
            }
            expect(new TextDecoder().decode(bytes)).toBe('reference bytes');
            const text = await new Response(
                file.createReadStream({ validation: 'crc32c' })
            ).text();
            expect(text).toBe('reference bytes');
            for (const version of ['v2', 'v4'] as const) {
                const { error, data } = await file.getSignedUrl({
                    action: 'read',
                    version,
                    expires: Date.now() + 300000
                });
                if (error) {
                    throw error;
                }
                const response = await fetch(data, {
                    signal: AbortSignal.timeout(30000)
                });
                const body = await response.text();
                expect(response.status, body).toBe(200);
                expect(body).toBe('reference bytes');
            }
            const { error: urlError, data: url } = await file.getDownloadURL();
            if (urlError) {
                throw urlError;
            }
            const response = await fetch(url, {
                signal: AbortSignal.timeout(30000)
            });
            const tokenText = await response.text();
            expect(response.status, tokenText).toBe(200);
            expect(tokenText).toBe('reference bytes');
            const { error: copyError, data: copy } = await file.copy(
                `${prefix}admin-copy`,
                { metadata: { copied: 'yes' } }
            );
            if (copyError) {
                throw copyError;
            }
            expect(copy.metadata?.metadata?.copied).toBe('yes');
            const { error: moveError, data: moved } = await copy.move(
                `${prefix}admin-moved`
            );
            if (moveError) {
                throw moveError;
            }
            const { error: listError, data: page } = await bucket.getFiles({
                prefix,
                autoPaginate: false,
                maxResults: 1
            });
            if (listError) {
                throw listError;
            }
            expect(page.files.length).toBe(1);
            expect(typeof page.files[0]?.download).toBe('function');
            const stream = bucket
                .file(`${prefix}admin-stream`)
                .createWriteStream();
            const writer = stream.getWriter();
            await writer.write(new TextEncoder().encode('stream bytes'));
            await writer.close();
            const { error: writeError, data: written } = await stream.result;
            if (writeError) {
                throw writeError;
            }
            expect(written.size).toBe('12');
            const { error: deleteError } = await moved.delete();
            if (deleteError) {
                throw deleteError;
            }
            const { error: missingError } = await moved.delete({
                ignoreNotFound: true
            });
            if (missingError) {
                throw missingError;
            }
        }, 120000);

        it('validates MD5 for multipart and resumable Web Stream uploads', async () => {
            const bucket = storage!.bucket();
            for (const resumable of [false, true]) {
                const file = bucket.file(`${prefix}md5-${resumable}`);
                const { error: saveError } = await file.save('MD5 edge bytes', {
                    resumable,
                    validation: 'md5',
                    metadata: { metadata: { numeric: 42, enabled: true } }
                });
                if (saveError) {
                    throw saveError;
                }
                expect(file.metadata?.md5Hash).toBeTruthy();
                const { error: metadataError, data: metadata } =
                    await file.getMetadata();
                if (metadataError) {
                    throw metadataError;
                }
                expect(metadata.metadata?.numeric).toBe('42');
                const { error: downloadError, data: bytes } =
                    await file.download({ validation: 'md5' });
                if (downloadError) {
                    throw downloadError;
                }
                expect(new TextDecoder().decode(bytes)).toBe('MD5 edge bytes');
                const streamed = await new Response(
                    file.stream({ validation: 'md5' })
                ).text();
                expect(streamed).toBe('MD5 edge bytes');
                const { error: rangeError, data: suffix } = await file.download(
                    { end: -5 }
                );
                if (rangeError) {
                    throw rangeError;
                }
                expect(new TextDecoder().decode(suffix)).toBe('bytes');
            }
            const { error, data } = await bucket.getFiles({
                prefix: `${prefix}md5-`,
                fields: 'items(md5Hash)',
                autoPaginate: false
            });
            if (error) {
                throw error;
            }
            expect(data.files).toHaveLength(2);
            expect(data.files.every((file) => !!file.metadata?.md5Hash)).toBe(
                true
            );
        }, 120000);

        it('resumes sliced input with a saved CRC32C through File.save', async () => {
            const file = storage!.bucket().file(`${prefix}sliced-resume`);
            const preceding = new Uint8Array(262144).fill(65);
            const { error: sessionError, data: uri } =
                await file.createResumableUpload({
                    size: preceding.byteLength + 3
                });
            if (sessionError) {
                throw sessionError;
            }
            const { error: chunkError, data: progress } =
                await storage!.uploadChunk(uri, preceding, {
                    offset: 0,
                    totalSize: preceding.byteLength + 3
                });
            if (chunkError) {
                throw chunkError;
            }
            expect(progress).toMatchObject({
                complete: false,
                nextOffset: preceding.byteLength
            });
            const resumeCRC32C = await calculateStorageCrc32c(preceding);
            const { error: saveError } = await file.save('end', {
                uri,
                offset: preceding.byteLength,
                resumeCRC32C
            });
            if (saveError) {
                throw saveError;
            }
            const { error: downloadError, data: bytes } = await file.download({
                validation: 'crc32c'
            });
            if (downloadError) {
                throw downloadError;
            }
            expect(bytes.byteLength).toBe(preceding.byteLength + 3);
            expect(new TextDecoder().decode(bytes.slice(-3))).toBe('end');
        }, 60000);

        it('leaves a Web writable upload incomplete and finalizes from its custom CRC checkpoint', async () => {
            const file = storage!.bucket().file(`${prefix}partial-checkpoint`, {
                crc32cGenerator: () => new StorageCrc32c()
            });
            const bytes = new Uint8Array(262144).fill(42);
            let sessionUri: string | undefined;
            let completed = false;
            try {
                const writable = file.createWriteStream({
                    isPartialUpload: true,
                    chunkSize: bytes.length,
                    onSession(uri) {
                        sessionUri = uri;
                    }
                });
                await new Blob([bytes]).stream().pipeTo(writable);
                const { error, data } = await writable.result;
                if (error) {
                    throw error;
                }
                expect(data).toMatchObject({
                    complete: false,
                    nextOffset: bytes.length
                });
                expect(file.metadata).toBeUndefined();
                const { error: statusError, data: status } =
                    await storage!.getUploadStatus(data.sessionUri);
                if (statusError) {
                    throw statusError;
                }
                expect(status).toEqual({
                    complete: false,
                    nextOffset: bytes.length
                });
                const { error: saveError } = await file.save('end', {
                    uri: data.sessionUri,
                    offset: data.nextOffset,
                    resumeCRC32C: data.crc32c
                });
                if (saveError) {
                    throw saveError;
                }
                completed = true;
                const { error: downloadError, data: downloaded } =
                    await file.download({ validation: 'crc32c' });
                if (downloadError) {
                    throw downloadError;
                }
                expect(downloaded.byteLength).toBe(bytes.length + 3);
                expect(downloaded.slice(0, bytes.length)).toEqual(bytes);
                expect(new TextDecoder().decode(downloaded.slice(-3))).toBe(
                    'end'
                );
            } finally {
                if (sessionUri && !completed) {
                    const { error } = await storage!.cancelUpload(sessionUri);
                    if (error) {
                        throw error;
                    }
                }
            }
        }, 60000);

        it('composes files and reads bucket metadata and permissions', async () => {
            for (const [name, text] of [
                ['part1', 'a'],
                ['part2', 'b']
            ]) {
                const { error } = await storage!.upload(
                    `${prefix}${name}`,
                    text!
                );
                if (error) {
                    throw error;
                }
            }
            const { error: composeError } = await storage!.compose(
                `${prefix}combined`,
                [{ name: `${prefix}part1` }, { name: `${prefix}part2` }],
                { ifGenerationMatch: '0' }
            );
            if (composeError) {
                throw composeError;
            }
            const { error: readError, data: bytes } = await storage!.download(
                `${prefix}combined`
            );
            if (readError) {
                throw readError;
            }
            expect(new TextDecoder().decode(bytes)).toBe('ab');
            const { error: bucketError, data: bucket } =
                await storage!.getBucketMetadata();
            if (bucketError) {
                throw bucketError;
            }
            expect(bucket.name).toBe(storage!.bucketName);
            const { error: permissionsError, data: permissions } =
                await storage!.testIamPermissions(['storage.objects.get']);
            if (permissionsError) {
                throw permissionsError;
            }
            expect(permissions).toContain('storage.objects.get');
        });
    }
);

describe.skipIf(process.env.STORAGE_ADMIN_LIVE_TESTS !== '1')(
    'live Storage administration in a dedicated temporary bucket',
    () => {
        const bucketName = `fae-storage-admin-${crypto.randomUUID()}`;
        let storage: Storage;
        let account: ServiceAccount;
        let created = false;
        let folderCreated = false;

        beforeAll(async () => {
            const raw =
                process.env.PRIVATE_FIREBASE_ADMIN_CONFIG ??
                (process.env.GOOGLE_APPLICATION_CREDENTIALS
                    ? readFileSync(
                          process.env.GOOGLE_APPLICATION_CREDENTIALS,
                          'utf8'
                      )
                    : '');
            account = JSON.parse(raw || '{}') as ServiceAccount;
            if (
                !account.client_email ||
                !account.private_key ||
                !account.project_id
            ) {
                throw new Error(
                    'Live administration tests require service account credentials with a project ID.'
                );
            }
            const cache = new TokenCache();
            storage = new Storage(account, {
                bucketName,
                fetch: (input, init) =>
                    fetch(input, {
                        ...init,
                        signal: AbortSignal.timeout(30000)
                    }),
                cache: {
                    getCache: cache.get.bind(cache),
                    setCache: cache.set.bind(cache)
                }
            });
            const { error } = await storage.createBucket({
                location: process.env.STORAGE_TEST_LOCATION ?? 'US',
                iamConfiguration: {
                    uniformBucketLevelAccess: { enabled: true },
                    publicAccessPrevention: 'enforced'
                },
                softDeletePolicy: { retentionDurationSeconds: '604800' },
                versioning: { enabled: true },
                labels: { suite: 'firebase-admin-edge' }
            });
            if (error) {
                throw error;
            }
            created = true;
        }, 60000);

        afterAll(async () => {
            if (!created) {
                return;
            }
            if (
                storage.bucketName !== bucketName ||
                !bucketName.startsWith('fae-storage-admin-')
            ) {
                throw new Error(
                    'Refusing cleanup outside the dedicated test bucket.'
                );
            }
            for (let attempt = 0; attempt < 5; attempt++) {
                const { error: policyError } =
                    await storage.updateBucketMetadata({
                        softDeletePolicy: { retentionDurationSeconds: '0' }
                    });
                if (!policyError) {
                    break;
                }
                if (
                    policyError.code !== 'storage/quota-exceeded' ||
                    attempt === 4
                ) {
                    throw policyError;
                }
                await new Promise((resolve) =>
                    setTimeout(resolve, 2000 * (attempt + 1))
                );
            }
            let pageToken: string | undefined;
            const targets: Array<{ name: string; generation: string }> = [];
            do {
                const { error, data } = await storage.listFiles({
                    versions: true,
                    pageToken
                });
                if (error) {
                    throw error;
                }
                targets.push(
                    ...data.files.map(({ name, generation }) => ({
                        name,
                        generation
                    }))
                );
                pageToken = data.nextPageToken;
            } while (pageToken);
            const { error: batchError, data: deleted } =
                await storage.deleteFiles(targets, { ignoreNotFound: true });
            if (batchError) {
                throw batchError;
            }
            for (const { error } of deleted.results) {
                if (error) {
                    throw error;
                }
            }
            if (folderCreated) {
                const { error } = await storage.deleteManagedFolder('managed/');
                if (error) {
                    throw error;
                }
            }
            const { error } = await storage.deleteBucket();
            if (error) {
                throw error;
            }
            created = false;
        }, 60000);

        it('provisions log-delivery permission only on its disposable bucket', async () => {
            const bucket = storage.bucket();
            const { error: policyError, data: original } =
                await bucket.iam.getPolicy();
            if (policyError) {
                throw policyError;
            }
            try {
                const { error } = await bucket.enableLogging({
                    prefix: 'test-logs/'
                });
                if (error) {
                    throw error;
                }
                const { error: readError, data: policy } =
                    await bucket.iam.getPolicy();
                if (readError) {
                    throw readError;
                }
                expect(
                    policy.bindings.some(
                        (binding) =>
                            binding.role === 'roles/storage.objectCreator' &&
                            binding.members.includes(
                                'group:cloud-storage-analytics@google.com'
                            )
                    )
                ).toBe(true);
            } finally {
                const { error: metadataError } = await bucket.setMetadata({
                    logging: null
                });
                if (metadataError) {
                    throw metadataError;
                }
                const { error: readError, data: current } =
                    await bucket.iam.getPolicy();
                if (readError) {
                    throw readError;
                }
                const { error: restoreError } = await bucket.iam.setPolicy({
                    ...original,
                    etag: current.etag
                });
                if (restoreError) {
                    throw restoreError;
                }
            }
        }, 60000);

        it('updates CORS, lifecycle, and bucket IAM with concurrency guards', async () => {
            const { error: readError, data: bucket } =
                await storage.getBucketMetadata();
            if (readError) {
                throw readError;
            }
            const { error: updateError, data: updated } =
                await storage.updateBucketMetadata(
                    {
                        cors: [
                            {
                                origin: ['https://example.com'],
                                method: ['GET'],
                                maxAgeSeconds: 60
                            }
                        ],
                        lifecycle: {
                            rule: [
                                {
                                    action: { type: 'Delete' },
                                    condition: {
                                        age: 30,
                                        matchesPrefix: ['expired/']
                                    }
                                }
                            ]
                        }
                    },
                    { ifMetagenerationMatch: bucket.metageneration }
                );
            if (updateError) {
                throw updateError;
            }
            expect(updated.cors?.[0]?.origin).toEqual(['https://example.com']);
            expect(updated.lifecycle?.rule[0]?.condition.age).toBe(30);
            const { error: policyError, data: original } =
                await storage.getIamPolicy();
            if (policyError) {
                throw policyError;
            }
            const binding = {
                role: 'roles/storage.objectViewer',
                members: [`serviceAccount:${account.client_email}`]
            };
            const { error: setError, data: changed } =
                await storage.setIamPolicy({
                    ...original,
                    bindings: [...original.bindings, binding]
                });
            if (setError) {
                throw setError;
            }
            try {
                expect(changed.bindings).toContainEqual(binding);
                const { error: permissionsError, data: permissions } =
                    await storage.testIamPermissions([
                        'storage.buckets.get',
                        'storage.objects.restore'
                    ]);
                if (permissionsError) {
                    throw permissionsError;
                }
                expect(permissions).toContain('storage.buckets.get');
            } finally {
                const { error } = await storage.setIamPolicy({
                    ...original,
                    etag: changed.etag
                });
                if (error) {
                    throw error;
                }
            }
        }, 60000);

        it('creates, lists, reads and deletes managed folders and updates their IAM policies', async () => {
            const { error: createError } =
                await storage.createManagedFolder('managed/');
            if (createError) {
                throw createError;
            }
            folderCreated = true;
            const { error: listError, data: page } =
                await storage.listManagedFolders({
                    prefix: 'managed/',
                    maxResults: 1
                });
            if (listError) {
                throw listError;
            }
            expect(page.items.map(({ name }) => name)).toEqual(['managed/']);
            const { error: getError, data: folder } =
                await storage.getManagedFolder('managed/');
            if (getError) {
                throw getError;
            }
            expect(folder.name).toBe('managed/');
            const { error: policyError, data: policy } =
                await storage.getManagedFolderIamPolicy('managed/');
            if (policyError) {
                throw policyError;
            }
            const { error: setError } = await storage.setManagedFolderIamPolicy(
                'managed/',
                {
                    ...policy,
                    bindings: [
                        {
                            role: 'roles/storage.objectViewer',
                            members: [`serviceAccount:${account.client_email}`]
                        }
                    ]
                }
            );
            if (setError) {
                throw setError;
            }
            const { error: permissionsError, data: permissions } =
                await storage.testManagedFolderIamPermissions('managed/', [
                    'storage.managedFolders.get'
                ]);
            if (permissionsError) {
                throw permissionsError;
            }
            expect(permissions).toContain('storage.managedFolders.get');
            const { error: deleteError } =
                await storage.deleteManagedFolder('managed/');
            if (deleteError) {
                throw deleteError;
            }
            folderCreated = false;
        }, 60000);

        it('soft-deletes and restores a specific object generation', async () => {
            const { error: uploadError, data: uploaded } = await storage.upload(
                'restore.txt',
                'restore me',
                { crc32c: 'auto', ifGenerationMatch: '0' }
            );
            if (uploadError) {
                throw uploadError;
            }
            const { error: deleteError } = await storage.delete('restore.txt', {
                generation: uploaded.generation,
                ifGenerationMatch: uploaded.generation
            });
            if (deleteError) {
                throw deleteError;
            }
            const { error: listError, data: page } = await storage.listFiles({
                softDeleted: true
            });
            if (listError) {
                throw listError;
            }
            expect(
                page.files.some(
                    ({ generation }) => generation === uploaded.generation
                )
            ).toBe(true);
            const { error: restoreError } = await storage.restore(
                'restore.txt',
                { generation: uploaded.generation, ifGenerationMatch: '0' }
            );
            if (restoreError) {
                throw restoreError;
            }
            const { error: downloadError, data: bytes } =
                await storage.download('restore.txt', { verifyChecksum: true });
            if (downloadError) {
                throw downloadError;
            }
            expect(new TextDecoder().decode(bytes)).toBe('restore me');
        }, 60000);
    }
);
