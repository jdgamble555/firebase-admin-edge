import { EncryptJWT, jwtDecrypt } from 'jose';
import { FirebaseEdgeError } from './errors.js';
import { isLocalRedirectPath } from './provider-session.js';

const PURPOSE = 'firebase-admin-edge:email-link';

/** Derive a purpose-specific encryption key from server-only key material. @internal */
async function emailLinkKey(secret: string) {
    if (!secret)
        throw new Error('Server key material is required for email links.');
    const bytes = new TextEncoder().encode(`${PURPOSE}\n${secret}`);
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    return new Uint8Array(digest);
}

/** Bind optional email and redirect state to this project and tenant for one hour. @internal */
export async function createEmailLinkState(
    state: { email?: string; next: string },
    secret: string,
    projectId: string,
    tenantId?: string
) {
    if (!isLocalRedirectPath(state.next))
        throw new Error('The next path must be a local absolute path.');
    const key = await emailLinkKey(secret);
    return new EncryptJWT({ ...state, tenantId: tenantId ?? null })
        .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
        .setIssuer(projectId)
        .setAudience(PURPOSE)
        .setIssuedAt()
        .setExpirationTime('1h')
        .encrypt(key);
}

/** Authenticate and decrypt email-link state before consuming the Firebase code. @internal */
export async function readEmailLinkState(
    token: string,
    secret: string,
    projectId: string,
    tenantId?: string
) {
    const key = await emailLinkKey(secret);
    const { payload } = await jwtDecrypt(token, key, {
        issuer: projectId,
        audience: PURPOSE,
        keyManagementAlgorithms: ['dir'],
        contentEncryptionAlgorithms: ['A256GCM']
    });
    if (
        payload.tenantId !== (tenantId ?? null) ||
        !isLocalRedirectPath(payload.next) ||
        (payload.email !== undefined && typeof payload.email !== 'string')
    )
        throw new Error('Invalid email-link state.');
    return { email: payload.email as string | undefined, next: payload.next };
}

export type EmailActionMode =
    | 'signIn'
    | 'resetPassword'
    | 'verifyAndChangeEmail'
    | 'verifyEmail'
    | 'recoverEmail';

/** Inspect an email action without consuming its code. OAuth callbacks return null. @internal */
export function parseEmailActionLink(
    input: URL,
    apiKey: string,
    tenantId?: string
) {
    let url = input;
    for (
        let depth = 0;
        depth < 3 && !url.searchParams.has('oobCode');
        depth++
    ) {
        const inner = url.searchParams.get('link');
        if (!inner) break;
        url = new URL(inner);
    }
    const mode = url.searchParams.get('mode');
    const code = url.searchParams.get('oobCode');
    if (
        !mode &&
        !['oobCode', 'emailLinkState', 'link'].some((key) =>
            url.searchParams.has(key)
        )
    )
        return null;
    const actionMode = mode ?? 'signIn';
    const key = url.searchParams.get('apiKey');
    const tenant = url.searchParams.get('tenantId');
    if (
        ![
            'signIn',
            'resetPassword',
            'verifyAndChangeEmail',
            'verifyEmail',
            'recoverEmail'
        ].includes(actionMode) ||
        (key !== null && key !== apiKey) ||
        (tenant !== null && tenant !== tenantId) ||
        (url.searchParams.has('link') && !code)
    )
        throw new FirebaseEdgeError({
            code: 'auth/invalid-action-code',
            message: 'Invalid or unsupported email action link.'
        });
    return {
        actionMode: actionMode as EmailActionMode,
        hasLink: Boolean(code?.trim()),
        code,
        url
    };
}

/** Parse sign-in state using the shared email-action parser. @internal */
export function parseEmailSignInLink(
    input: URL,
    apiKey: string,
    tenantId?: string
) {
    const action = parseEmailActionLink(input, apiKey, tenantId);
    if (
        !action ||
        action.actionMode !== 'signIn' ||
        !action.hasLink ||
        !action.code
    )
        throw new FirebaseEdgeError({
            code: 'auth/invalid-action-code',
            message: 'Invalid email sign-in link.'
        });
    const { url, code } = action;
    const continuation = url.searchParams.get('continueUrl');
    const state =
        url.searchParams.get('emailLinkState') ??
        (continuation
            ? new URL(continuation).searchParams.get('emailLinkState')
            : null);
    if (!state)
        throw new FirebaseEdgeError({
            code: 'auth/invalid-action-code',
            message: 'Email-link state is missing.'
        });
    return { code, state };
}
