/// <reference types="vite/client" />

import type { createFirebaseEdgeServer } from 'firebase-admin-edge';

declare global {
	namespace App {
		interface Locals {
			fbServer: ReturnType<typeof createFirebaseEdgeServer>;
		}
	}
}

export {};
