import type { createFirebaseEdgeServer } from 'firebase-admin-edge';

declare global {
	namespace App {
		interface Locals {
			authServer: ReturnType<typeof createFirebaseEdgeServer>;
		}
	}
}

export {};
