import { readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { getToken } from './google-oauth.js';
import { countAccounts, queryAccounts } from './firebase-auth-endpoints.js';
import { Identity } from './identity.js';
import type { ServiceAccount } from './firebase-types.js';
import type { IdentityReference } from './identity-reference.js';

describe.skipIf(process.env.IDENTITY_LIVE_TESTS !== '1')(
    'live Identity writes (temporary accounts)',
    () => {
        let identity: Identity;
        let user: IdentityReference<false, true>;
        let uid: string;
        const requests: string[] = [];
        const creationTime = '2020-01-02T03:04:05.000Z';
        const lastSignInTime = '2021-02-03T04:05:06.000Z';
        const epoch = 'Thu, 01 Jan 1970 00:00:00 GMT';

        beforeAll(() => {
            const raw =
                process.env.PRIVATE_FIREBASE_ADMIN_CONFIG ??
                (process.env.GOOGLE_APPLICATION_CREDENTIALS
                    ? readFileSync(
                          process.env.GOOGLE_APPLICATION_CREDENTIALS,
                          'utf8'
                      )
                    : '');
            const account: ServiceAccount = JSON.parse(raw);
            const transport: typeof fetch = (input, init) => {
                const url = new URL(
                    input instanceof Request ? input.url : input
                );
                const operation = url.pathname.match(/accounts:(\w+)$/)?.[1];
                if (operation) {
                    requests.push(operation);
                }
                return fetch(input, {
                    ...init,
                    signal: AbortSignal.timeout(20000)
                });
            };
            identity = new Identity(account, {
                emulatorHost: null,
                fetch: transport
            });
        });

        beforeEach(async () => {
            uid = `identity-write-test-${randomUUID()}`;
            user = identity.users().byUid(uid);
            const { error, data } = await identity.users().add({
                uid,
                email: `${uid}@example.com`,
                displayName: 'Regression fixture',
                photoURL: 'https://example.com/avatar.png',
                disabled: true,
                emailVerified: true
            });
            expect(error).toBeNull();
            expect(data).toEqual({ uid });
            requests.length = 0;
        });

        afterEach(async () => {
            // Only this test's random UID is ever eligible for cleanup, including failed setup.
            if (!user) {
                return;
            }
            const { error, data } = await user.get();
            if (error) {
                throw error;
            }
            if (!data) {
                return;
            }
            const { error: deleteError } = await user.delete();
            if (deleteError) {
                throw deleteError;
            }
            const { error: lookupError, data: remaining } = await user.get();
            expect(lookupError).toBeNull();
            expect(remaining).toBeNull();
        });

        it('combines profile, claims, and metadata in one write and preserves omitted fields', async () => {
            const result = await user.update({
                displayName: 'Updated',
                customClaims: { role: 'editor', retained: true },
                metadata: { creationTime, lastSignInTime }
            });
            expect(result).toEqual({ error: null, data: { uid } });
            expect(requests).toEqual(['update']);

            requests.length = 0;
            const partial = await user.update({ displayName: 'Updated again' });
            expect(partial).toEqual({ error: null, data: { uid } });
            expect(requests).toEqual(['update']);
            const { error, data } = await user.get();
            expect(error).toBeNull();
            expect(data).toMatchObject({
                displayName: 'Updated again',
                customClaims: { role: 'editor', retained: true },
                metadata: {
                    creationTime: new Date(creationTime).toUTCString(),
                    lastSignInTime: new Date(lastSignInTime).toUTCString()
                }
            });

            const replacement = await user.update({
                customClaims: { role: 'reader' }
            });
            expect(replacement).toEqual({ error: null, data: { uid } });
            const { error: claimsError, data: claims } =
                await user.claims.get();
            expect(claimsError).toBeNull();
            expect(claims).toEqual({ role: 'reader' });
        });

        it.each([
            ['omitted', {}],
            ['null', { customClaims: null, metadata: null }],
            ['partial', { metadata: { creationTime } }]
        ] as const)(
            'set resets %s claims and timestamps',
            async (mode, reset) => {
                const seeded = await user.update({
                    customClaims: { role: 'editor' },
                    metadata: { creationTime, lastSignInTime }
                });
                expect(seeded).toEqual({ error: null, data: { uid } });
                requests.length = 0;
                const result = await user.set(reset);
                expect(result).toEqual({ error: null, data: { uid } });
                expect(requests).toEqual(['update']);
                const { error, data } = await user.get();
                expect(error).toBeNull();
                expect(data?.email).toBeUndefined();
                expect(data?.displayName).toBeUndefined();
                expect(data?.photoURL).toBeUndefined();
                expect(data).toMatchObject({
                    disabled: false,
                    emailVerified: false,
                    customClaims: {},
                    metadata: {
                        creationTime:
                            mode === 'partial'
                                ? new Date(creationTime).toUTCString()
                                : epoch,
                        lastSignInTime: epoch
                    }
                });
            }
        );

        it('reads and writes literal claim keys while preserving unrelated claims', async () => {
            const seeded = await user.claims.set({ retained: true });
            expect(seeded).toEqual({ error: null, data: { uid } });
            expect(requests).toEqual(['update']);
            const key = user.claims.byKey('some.field');
            const { error: missingError, data: missing } = await key.get();
            expect(missingError).toBeNull();
            expect(missing).toBeUndefined();

            for (const [operation, value] of [
                ['set', 'first'],
                ['update', null]
            ] as const) {
                requests.length = 0;
                const result = await key[operation](value);
                expect(result).toEqual({ error: null, data: { uid } });
                expect(requests).toEqual(['lookup', 'update']);
                const { error, data } = await key.get();
                expect(error).toBeNull();
                expect(data).toBe(value);
                const { error: claimsError, data: claims } =
                    await user.claims.get();
                expect(claimsError).toBeNull();
                expect(claims).toEqual({ retained: true, 'some.field': value });
            }

            requests.length = 0;
            const removed = await key.delete();
            expect(removed).toEqual({ error: null, data: { uid } });
            expect(requests).toEqual(['lookup', 'update']);
            const { error, data } = await user.claims.get();
            expect(error).toBeNull();
            expect(data).toEqual({ retained: true });

            requests.length = 0;
            const merged = await user.claims.update({ role: 'reader' });
            expect(merged).toEqual({ error: null, data: { uid } });
            expect(requests).toEqual(['lookup', 'update']);
            const { error: mergedError, data: mergedClaims } =
                await user.claims.get();
            expect(mergedError).toBeNull();
            expect(mergedClaims).toEqual({ retained: true, role: 'reader' });

            requests.length = 0;
            const cleared = await user.claims.delete();
            expect(cleared).toEqual({ error: null, data: { uid } });
            expect(requests).toEqual(['update']);
            const { error: clearError, data: clearedClaims } =
                await user.claims.get();
            expect(clearError).toBeNull();
            expect(clearedClaims).toEqual({});
        });

        it('updates metadata and revokes tokens without readbacks', async () => {
            const seeded = await user.metadata.update({
                creationTime,
                lastSignInTime
            });
            expect(seeded).toEqual({ error: null, data: { uid } });
            expect(requests).toEqual(['update']);
            requests.length = 0;
            const updated = await user.metadata.update({
                lastSignInTime: creationTime
            });
            expect(updated).toEqual({ error: null, data: { uid } });
            expect(requests).toEqual(['update']);
            const { error, data } = await user.metadata.get();
            expect(error).toBeNull();
            expect(data).toMatchObject({
                creationTime: new Date(creationTime).toUTCString(),
                lastSignInTime: new Date(creationTime).toUTCString()
            });
            requests.length = 0;
            const started = Math.floor(Date.now() / 1000) * 1000;
            const revoked = await user.metadata.revokeTokens();
            expect(revoked).toEqual({ error: null, data: { uid } });
            expect(requests).toEqual(['update']);
            const { error: lookupError, data: record } = await user.get();
            expect(lookupError).toBeNull();
            expect(
                Date.parse(record?.tokensValidAfterTime ?? '')
            ).toBeGreaterThanOrEqual(started);
        });

        it('normalizes deletion and reports missing users for resource reads and writes', async () => {
            const removed = await user.delete();
            expect(removed).toEqual({ error: null, data: { uid } });
            expect(requests).toEqual(['delete']);
            const lookup = await user.get();
            expect(lookup).toEqual({ error: null, data: null });
            for (const [operation, code] of [
                [() => user.claims.get(), 'auth/user-not-found'],
                [
                    () => user.claims.byKey('missing').get(),
                    'auth/user-not-found'
                ],
                [() => user.metadata.get(), 'auth/user-not-found'],
                [
                    () => user.update({ displayName: 'Missing' }),
                    'auth/endpoint-user-not-found'
                ],
                [() => user.set({}), 'auth/endpoint-user-not-found'],
                [
                    () => user.claims.set({ role: 'reader' }),
                    'auth/admin-set-custom-claims-failed'
                ]
            ] as const) {
                const { error, data } = await operation();
                expect(error).toMatchObject({ code });
                expect(data).toBeNull();
            }
        });
    }
);

describe.skipIf(process.env.IDENTITY_LIVE_TESTS !== '1')(
    'live Identity query capabilities (read-only)',
    () => {
        let account: ServiceAccount;
        let token: string;
        let uid: string | undefined;
        let email: string | undefined;
        let otherUid: string | undefined;

        beforeAll(async () => {
            const raw =
                process.env.PRIVATE_FIREBASE_ADMIN_CONFIG ??
                (process.env.GOOGLE_APPLICATION_CREDENTIALS
                    ? readFileSync(
                          process.env.GOOGLE_APPLICATION_CREDENTIALS,
                          'utf8'
                      )
                    : '');
            account = JSON.parse(raw);
            const { error, data } = await getToken(account);
            if (error) {
                throw error;
            }
            token = data.access_token;
            const { error: queryError, data: users } = await queryAccounts(
                token,
                account.project_id,
                { limit: 2 }
            );
            if (queryError) {
                throw queryError;
            }
            uid = users?.[0]?.localId;
            email = users?.[0]?.email;
            otherUid = users?.[1]?.localId;
        });

        it('applies only the first expression, not AND or OR', async (context) => {
            if (!uid) {
                context.skip();
                return;
            }
            const missing = `identity-probe-${randomUUID()}`;
            for (const [expressions, expected] of [
                [[{ userId: uid }, { userId: missing }], 1],
                [[{ userId: missing }, { userId: uid }], 0],
                [[{ userId: uid }, { email: `${missing}@example.com` }], 1],
                [[{ email: `${missing}@example.com` }, { userId: uid }], 0]
            ] as const) {
                // Deliberately bypass the builder to establish the backend's semantics.
                const transport: typeof fetch = (input, init) => {
                    const body = JSON.parse(init?.body as string);
                    return fetch(input, {
                        ...init,
                        body: JSON.stringify({
                            ...body,
                            expression: expressions
                        }),
                        signal: AbortSignal.timeout(20000)
                    });
                };
                const { error, data } = await countAccounts(
                    token,
                    account.project_id,
                    undefined,
                    undefined,
                    transport
                );
                expect(error).toBeNull();
                expect(data).toBe(expected);
            }
        });

        it('does not send malformed email filters that the backend would ignore', async () => {
            const identity = new Identity(account, { emulatorHost: null });
            expect(() =>
                identity.users().where('email', '==', 'not-an-email')
            ).toThrow();
            const { error, data: total } = await countAccounts(
                token,
                account.project_id
            );
            expect(error).toBeNull();
            const { error: malformedError, data: malformedTotal } =
                await countAccounts(token, account.project_id, {
                    field: 'email',
                    value: 'not-an-email'
                });
            expect(malformedError).toBeNull();
            expect(malformedTotal).toBe(total);
        });

        it('supports exact case-insensitive email queries and mixed OR lookups', async (context) => {
            if (!uid || !email || !otherUid) {
                context.skip();
                return;
            }
            const identity = new Identity(account, { emulatorHost: null });
            const { error, data } = await identity
                .users()
                .where('email', '==', email.toUpperCase())
                .count()
                .get();
            expect(error).toBeNull();
            expect(data?.count).toBeGreaterThan(0);
            const { error: lookupError, data: matches } = await identity
                .users()
                .or('uid', '==', otherUid)
                .or('email', '==', email)
                .get();
            expect(lookupError).toBeNull();
            expect(matches?.users.some((user) => user.uid === uid)).toBe(true);
            expect(matches?.users.some((user) => user.uid === otherUid)).toBe(
                true
            );
        });

        it('accepts all native sort fields, directions, and offset pagination', async () => {
            const identity = new Identity(account, { emulatorHost: null });
            for (const field of [
                'uid',
                'email',
                'displayName',
                'createdAt',
                'lastLoginAt'
            ] as const) {
                for (const direction of ['asc', 'desc'] as const) {
                    const { error, data } = await identity
                        .users()
                        .orderBy(field, direction)
                        .offset(1)
                        .limit(1)
                        .get();
                    expect(error).toBeNull();
                    expect(data?.users.length).toBeLessThanOrEqual(1);
                }
            }
        });
    }
);
