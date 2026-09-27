import { checkWebRuntime, checkLiveEdge } from './runtime-checks.js';

export default {
    async fetch(
        request: Request,
        env: {
            PRIVATE_FIREBASE_ADMIN_CONFIG?: string;
            FIRESTORE_TEST_DATABASE_ID?: string;
        }
    ): Promise<Response> {
        if (
            request.method !== 'POST' ||
            new URL(request.url).pathname !== '/validate'
        )
            return new Response('Not found', { status: 404 });
        if (request.headers.get('X-Local-Validation') !== '1')
            return new Response('Missing local validation header', {
                status: 403
            });
        try {
            const portable = await checkWebRuntime();
            const account = JSON.parse(
                env.PRIVATE_FIREBASE_ADMIN_CONFIG ?? '{}'
            );
            const live = await checkLiveEdge(
                account,
                env.FIRESTORE_TEST_DATABASE_ID
            );
            return Response.json({ runtime: 'workerd', portable, live });
        } catch (error) {
            return Response.json(
                {
                    error:
                        error instanceof Error
                            ? error.message
                            : 'Validation failed'
                },
                { status: 500 }
            );
        }
    }
};
