import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        exclude: ['app-demo/**', 'node_modules/**', 'dist/**']
    }
});
