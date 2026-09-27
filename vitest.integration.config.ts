import { existsSync } from 'node:fs';
import { loadEnvFile } from 'node:process';
import { defineConfig } from 'vitest/config';

if (existsSync('.env')) loadEnvFile('.env');
process.env.FIRESTORE_LIVE_TESTS = '1';
process.env.STORAGE_LIVE_TESTS = '1';

export default defineConfig({
    test: {
        include: [
            'src/db/firestore.integration.test.ts',
            'src/storage/storage.integration.test.ts'
        ],
        fileParallelism: false,
        testTimeout: 60000,
        hookTimeout: 120000,
        retry: 0
    }
});
