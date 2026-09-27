import { expect, it } from 'vitest';
import { parseExplainMetrics, validateExplainOptions } from './explain.js';
it('decodes planning and execution metrics without losing duration precision', () => {
    expect(parseExplainMetrics({ planSummary: {} })).toEqual({
        planSummary: { indexesUsed: [] },
        executionStats: null
    });
    const metrics = parseExplainMetrics({
        planSummary: { indexesUsed: [{ properties: '(a ASC)' }] },
        executionStats: {
            resultsReturned: '12',
            readOperations: '15',
            executionDuration: '1.000000001s',
            debugStats: { billable: 12 }
        }
    });
    expect(metrics.executionStats).toEqual({
        resultsReturned: 12,
        readOperations: 15,
        executionDuration: { seconds: 1, nanoseconds: 1 },
        debugStats: { billable: 12 }
    });
    expect(() => validateExplainOptions({ analyze: true })).not.toThrow();
    expect(() => validateExplainOptions({})).not.toThrow();
});
it.each([
    null,
    {},
    { planSummary: { indexesUsed: 1 } },
    { planSummary: {}, executionStats: { executionDuration: 'bad' } },
    { planSummary: {}, executionStats: { readOperations: '-1' } }
])('rejects malformed metrics', (value) => {
    expect(() => parseExplainMetrics(value)).toThrow();
});
it.each([null, [], { analyze: 1 }])('rejects invalid options', (value) => {
    expect(() => validateExplainOptions(value as never)).toThrow();
});
