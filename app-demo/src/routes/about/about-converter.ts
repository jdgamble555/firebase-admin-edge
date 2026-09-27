import { error } from '@sveltejs/kit';
import type { FirestoreDataConverter } from 'firebase-admin-edge';

export type About = {
	name: string;
	description: string;
};

export const aboutConverter: FirestoreDataConverter<About> = {
	toFirestore({ name, description }) {
		return { name, description };
	},

	fromFirestore(snapshot) {
		const name = snapshot.get('name');

		if (typeof name !== 'string') {
			error(500, 'The about document must have a name string.');
		}

		const description = snapshot.get('description');

		if (typeof description !== 'string') {
			error(500, 'The about document must have a description string.');
		}

		return { name, description };
	}
};
