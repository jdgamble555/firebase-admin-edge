import { PRIVATE_FIREBASE_ADMIN_CONFIG } from '$env/static/private';
import { PUBLIC_FIREBASE_CONFIG } from '$env/static/public';
import { createFirebaseEdgeServer, TokenCache } from 'firebase-admin-edge';
import type { Handle } from '@sveltejs/kit';

const serviceAccount = JSON.parse(PRIVATE_FIREBASE_ADMIN_CONFIG);
const firebaseConfig = JSON.parse(PUBLIC_FIREBASE_CONFIG);

const cache = new TokenCache();

export const handle: Handle = async ({ event, resolve }) => {
	event.locals.fbServer = createFirebaseEdgeServer({
		serviceAccount,
		firebaseConfig,
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
