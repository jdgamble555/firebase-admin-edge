// See https://svelte.dev/docs/kit/types#app.d.ts

import type { createFirebaseEdgeServer } from "firebase-admin-edge";

// for information about these interfaces
declare global {
	namespace App {
		// interface Error {}
		interface Locals {
			authServer: ReturnType<typeof createFirebaseEdgeServer>
		}
		// interface PageData {}
		// interface PageState {}
		// interface Platform {}
	}
}

export { };
