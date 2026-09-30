import * as v from 'valibot';
import { FIREBASE_PROVIDER_IDS } from 'firebase-admin-edge';

export const emailSchema = v.pipe(
	v.string('Enter your email address.'),
	v.trim(),
	v.email('Enter a valid email address.')
);

const providerIds = Object.values(FIREBASE_PROVIDER_IDS);
export const linkProviderSchema = v.picklist(
	providerIds.filter((provider) => provider !== 'playgames.google.com'),
	'Unsupported provider'
);
export const unlinkProviderSchema = v.pipe(
	v.string('No provider specified'),
	v.nonEmpty('No provider specified'),
	v.picklist([...providerIds, 'email'], 'Unsupported provider')
);

// Optional fields serve several callback forms. Core validates the active action,
// password confirmation, and Firebase password policy. Never trim passwords.
export const callbackSchema = v.object({
	email: v.optional(v.union([v.literal(''), emailSchema]), ''),
	password: v.optional(v.string('Enter a valid password.'), ''),
	confirmPassword: v.optional(v.string('Enter a valid password confirmation.'), '')
});
