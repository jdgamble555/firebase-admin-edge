# Package memory: firebase-admin-edge

These instructions apply to all work in this repository.

- Always use guard clauses: handle invalid inputs, exceptional conditions, and early exits at the start of a function so the main logic stays flat.
- Keep higher-level methods focused on coordinating operations. Always reuse existing abstractions before adding new logic; inspect the relevant helpers first.
- Put API URLs, paths, HTTP methods, request construction, and API error mapping in the endpoint layer, using shared helpers such as `createAdminIdentityURL` and `restFetch`. Higher-level auth and server methods should call endpoint functions instead of implementing transport details themselves.
- Keep complex response parsing and data conversion in focused helpers. Higher-level methods should work with meaningful inputs and results, delegating implementation details to the appropriate layer. Extend existing helpers when needed rather than duplicating their logic or adding unnecessary abstraction layers.
- For every function added, always add tests in the same change. Cover its expected behavior and relevant guard clauses and edge cases using the existing Vitest setup.
- Organize tests by the module they cover, next to the implementation (`<module>.test.ts`). Add method tests to the existing module test file instead of creating a separate feature test file. Keep admin orchestration tests in `firebase-admin-auth.test.ts`, endpoint/request tests in `firebase-auth-endpoints.test.ts`, and user-record conversion tests in `user-record.test.ts`; mock lower-level dependencies when testing higher-level behavior.
- For every function added, always add a usage example to the root `README.md` in the same change. For internal helpers, demonstrate the behavior through the public API that uses them.
- Run `npm test` after adding or changing functions and their tests.
