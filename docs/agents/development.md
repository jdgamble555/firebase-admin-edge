# Agent development rules

These instructions apply to all work in this repository. Paths below are relative
to the repository root.

- Always use guard clauses: handle invalid inputs, exceptional conditions, and early exits at the start of a function so the main logic stays flat.
- Never put an `await` expression inside a function, method, or constructor call's arguments. Await the operation in a preceding statement, assign its result to a clearly named variable, and pass that variable to the call. Apply this convention to implementation code, tests, and examples.
- Keep higher-level methods focused on coordinating operations. Always reuse existing abstractions before adding new logic; inspect the relevant helpers first.
- Put API URLs, paths, HTTP methods, request construction, and API error mapping in the endpoint layer, using shared helpers such as `createAdminIdentityURL` and `restFetch`. Higher-level auth and server methods should call endpoint functions instead of implementing transport details themselves.
- Keep complex response parsing and data conversion in focused helpers. Higher-level methods should work with meaningful inputs and results, delegating implementation details to the appropriate layer. Extend existing helpers when needed rather than duplicating their logic or adding unnecessary abstraction layers.
- For every function added, always add tests in the same change. Cover its expected behavior and relevant guard clauses and edge cases using the existing Vitest setup.
- Organize tests by the module they cover, next to the implementation (`<module>.test.ts`). Add method tests to the existing module test file instead of creating a separate feature test file. Keep admin orchestration tests in `firebase-admin-auth.test.ts`, endpoint/request tests in `firebase-auth-endpoints.test.ts`, and user-record conversion tests in `user-record.test.ts`; mock lower-level dependencies when testing higher-level behavior.
- For every function added, always add a usage example in the same change. Put class method examples in that class's Markdown guide under `docs/`, and standalone function examples in `docs/FUNCTIONS.md`. Keep the root `README.md` focused on server setup and usage, linking to class guides instead of duplicating them. For internal helpers, demonstrate the behavior through the public API that uses them.
- Run `npm test` after adding or changing functions and their tests.

- Always simplify and prettify code you touch: prefer clear names, flat control flow, and existing shared helpers; remove unnecessary branches and duplication, and run Prettier on changed files.
- Destructure result objects as `{ error, data }` (or only the fields needed), using aliases when necessary, instead of reading `result.error` and `result.data`. Apply this to implementation code and usage examples.

- Prioritize readability over compactness. Separate validation, auth/API operations, and responses with blank lines, and leave a blank line between action handlers. Use braced guard clauses instead of dense one-line conditionals. Add only brief comments that explain intent or non-obvious behavior; do not narrate every statement.
