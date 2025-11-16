import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        exclude: ['fae-demo/**', 'node_modules/**', 'dist/**']
    }
});
