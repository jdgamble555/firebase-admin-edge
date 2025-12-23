import {
	PRIVATE_FIREBASE_ADMIN_CONFIG,
	PRIVATE_GITHUB_CLIENT_SECRET,
	PRIVATE_GOOGLE_CLIENT_SECRET
} from '$env/static/private';
import {
	PUBLIC_FIREBASE_CONFIG,
	PUBLIC_GITHUB_CLIENT_ID,
	PUBLIC_GOOGLE_CLIENT_ID
} from '$env/static/public';
import { createFirebaseEdgeServer, TokenCache } from 'firebase-admin-edge';
import type { Handle } from '@sveltejs/kit';

const serviceAccount = JSON.parse(PRIVATE_FIREBASE_ADMIN_CONFIG);
const firebaseConfig = JSON.parse(PUBLIC_FIREBASE_CONFIG);

const cache = new TokenCache();

export const handle: Handle = async ({ event, resolve }) => {
	event.locals.authServer = createFirebaseEdgeServer({
		serviceAccount,
		firebaseConfig,
		providers: {
			google: {
				client_id: PUBLIC_GOOGLE_CLIENT_ID,
				client_secret: PRIVATE_GOOGLE_CLIENT_SECRET
			},
			github: {
				client_id: PUBLIC_GITHUB_CLIENT_ID,
				client_secret: PRIVATE_GITHUB_CLIENT_SECRET
			}
		},
		cookies: {
			getSession: (name) => event.cookies.get(name),
			saveSession: (name, value, options) => event.cookies.set(name, value, options)
		},
		cache: {
			setCache: (name, value, ttl_ms) => cache.set(name, value, ttl_ms),
			getCache: (name) => cache.get(name)
		},
		redirectUri: event.url.origin + '/auth/callback',
		fetch: event.fetch,
		autoLinkProviders: true
	});

	return resolve(event);
};
