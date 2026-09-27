export type ProviderSession = {
    sessionId: string;
    next: string;
    intent: 'signin' | 'link';
};

/** Validate redirect paths at both flow creation and callback consumption. @internal */
export function isLocalRedirectPath(value: unknown): value is string {
    if (typeof value !== 'string') return false;
    return (
        value.startsWith('/') &&
        !value.startsWith('//') &&
        !/[\\\r\n]/.test(value)
    );
}

/** Read an untrusted serialized authorization session. @internal */
export function parseProviderSession(stored: string): ProviderSession | null {
    let value: unknown;
    try {
        value = JSON.parse(stored);
    } catch {
        return null;
    }
    if (!value || typeof value !== 'object' || Array.isArray(value))
        return null;
    const flow = value as Record<string, unknown>;
    if (
        typeof flow.sessionId !== 'string' ||
        !flow.sessionId ||
        !isLocalRedirectPath(flow.next) ||
        (flow.intent !== 'signin' && flow.intent !== 'link')
    )
        return null;
    return { sessionId: flow.sessionId, next: flow.next, intent: flow.intent };
}
