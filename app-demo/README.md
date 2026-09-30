# Firebase Edge Demo

A small SvelteKit app demonstrating server-side Firebase authentication and
Firestore access through `firebase-admin-edge`. Google, GitHub, and magic links
share `/auth/callback`; authentication runs in server loads and form actions.

## Setup

Build the package from the repository root with `npm install` and `npm run build`.
Then run `npm install` and `npm run dev` inside `app-demo`.

Configure these environment variables in `.env` or your hosting environment:

```dotenv
PRIVATE_FIREBASE_ADMIN_CONFIG='{"project_id":"your-project","client_email":"your-service-account","private_key":"your-private-key"}'
PUBLIC_FIREBASE_CONFIG='{"apiKey":"your-web-api-key","authDomain":"your-project.firebaseapp.com","projectId":"your-project","appId":"your-app-id"}'
```

Use your project's actual service account and web app configuration. Keep service
account credentials private and out of source control. The public config identifies
the Firebase project; it is not a Google or GitHub OAuth client secret.

`src/hooks.server.ts` creates `event.locals.fbServer` for each request, connects
SvelteKit cookies, shares a token cache, and sets `redirectUri` to the request
origin plus `/auth/callback`. Server files use `locals.fbServer` directly.
The root layout returns the signed-in user to pages.

## Google and GitHub

Enable each provider in Firebase Console, configure its credentials there, and
authorize the demo domain. Set the provider application's OAuth callback to the
Firebase handler shown in Console (usually
`https://your-project.firebaseapp.com/__/auth/handler`). Firebase handles the
provider exchange and returns to the demo's `/auth/callback`.

The demo does not accept separate Google or GitHub secrets. It calls
`getProviderLoginURL('google', next)` or `getProviderLoginURL('github', next)` and
completes sign-in with `handleCallback(url)`. `autoLinkProviders: true` enables
the core's supported automatic account-linking flow. The dashboard offers explicit
provider linking and unlinking with a confirmation dialog.

See the [server guide](../docs/FIREBASE_EDGE_SERVER.md) for supported providers, all
factory options, callback handling, and account-linking behavior.

## Magic-Link Sign-In

Enable Email/Password and Email link (passwordless sign-in) in Firebase Console.
Authorize the demo domain and configure the email action handler URL in template
settings as `https://your-demo-domain/auth/callback`, using HTTPS in production.

The login form calls:

```ts
const { error } = await fbServer.sendSignInLinkToEmail(email, '/dashboard', {
	includeEmailInLink: true
});
if (error) throw error;
```

Email is carried inside encrypted link state, so the link works on another device
without an email cookie. Keep the service account key stable between sending and
completion. The shared callback preserves the query and completes sign-in with
`handleCallback(url)` on a confirmation POST; opening the page alone does not
consume the code. Successful sign-in redirects to `/dashboard`.

If the link was sent without email in its state, the confirmation page asks for it
after `auth/missing-email`. Invalid or expired links show an error. Users should
only confirm links they requested: forwarding a link also forwards the ability to
sign in. See [all magic-link options](../docs/FIREBASE_EDGE_SERVER.md#magic-link-sign-in).

## Password Reset and Change Email

- Choose **Reset password** on `/dashboard`, enter the account email at
  `/reset-password`, and open the emailed link. The shared callback shows password
  and confirmation fields. Submit to complete the reset.
- While signed in, open `/change-email`, enter a new email address, and confirm the link sent there.
  The original email remains until verification succeeds. A session older than
  five minutes requires signing out and back in before requesting the change.

Enable Email/Password in Firebase Console. Under Authentication > Templates,
configure email action links to use `https://your-demo-domain/auth/callback`.
Firebase delivers the messages using its templates; no SMTP credentials or browser
Firebase SDK are needed. Password reset affects the Firebase password, not a Google
or GitHub password. Email changes do not change upstream provider profiles.

```ts
// /reset-password server action
const { error: sentError } = await fbServer.sendPasswordResetEmail(email);
if (sentError) throw sentError;

// Authenticated /change-email action
const { error: changeError } = await fbServer.verifyBeforeUpdateEmail(newEmail);
if (changeError) throw changeError;

// One callback POST handler for all flows
const { error, data } = await fbServer.handleCallback(url, {
	email,
	newPassword: password,
	confirmPassword
});
if (error) throw error;
// Redirect for data.type === 'redirect'; otherwise show its message.
```

The callback handles `resetPassword`, `verifyAndChangeEmail`, `verifyEmail`, and
`recoverEmail`, alongside existing sign-in. Code-consuming actions run only on POST.
Successful account changes clear the local session and offer a link to sign in
again. Reset delivery uses the same message for existing and unknown accounts.
See [the full API guide](../docs/FIREBASE_EDGE_SERVER.md#password-reset-and-email-changes).

## Firestore Example

`/about` loads `about/ZlNJrKd6LcATycPRmBPA` using
`locals.fbServer.firestore.doc(...).withConverter(aboutConverter).get()` in
`+page.server.ts`. Create that document with `name` and `description` fields or
change the path for your project. A missing document returns a 404. The converter
keeps the data passed to the Svelte page serializable.

## Checks and Production

```sh
npm run check
npm test
npm run build
npm run preview
```

Tests cover server actions, browser components, and a Playwright smoke test. They
do not send real authentication emails or verify a live provider sign-in. Configure
the SvelteKit adapter and private environment variables for your deployment.

The callback load calls `fbServer.getCallbackAction(url)` and renders its
`{ hasLink, actionMode }` result for email actions. It completes provider callbacks
with `fbServer.handleCallback(url)`. The POST action also uses `handleCallback`,
passing submitted fields. Mode detection, wrapped-link parsing, password matching,
and account-action dispatch live in the core, not the SvelteKit route.
See [shared callback handling](../docs/FIREBASE_EDGE_SERVER.md#shared-callback-handling).

## Form Validation

The dashboard reads enabled standard providers with
`fbServer.identity.providers.get()` and compares them with the signed-in user's
linked identities. Enabled browser providers can be connected; already-linked
providers remain available to disconnect even if disabled in the project. Linking
checks the enabled list again on submission. Play Games uses a native credential
flow, so the dashboard only offers disconnecting it when already linked.

Provider discovery requires the service account's `firebaseauth.configs.get`
permission. The current provider discovery API covers standard federated providers;
local sign-in methods and custom OIDC/SAML providers are not discovered here.

The demo uses Valibot's `safeParse` with shared schemas in
`src/lib/form-schemas.ts`. Email forms trim and validate addresses, provider forms
allow only supported choices, and the callback rejects non-text fields while
preserving passwords exactly. Validation failures return HTTP 400 before any
Firebase request. Action detection, password matching, and password policy stay
in the framework-independent core and Firebase.

```ts
import { safeParse } from 'valibot';
import { emailSchema } from '$lib/form-schemas';

const form = await request.formData();
const { success, output: email, issues } = safeParse(emailSchema, form.get('email'));
if (!success) return fail(400, { message: issues[0].message });
const { error } = await fbServer.sendPasswordResetEmail(email);
if (error) return fail(400, { message: error.message });
```

See [Valibot's parsing guide](https://valibot.dev/guides/parse-data/).
