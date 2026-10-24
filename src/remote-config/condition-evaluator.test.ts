import { createHash } from 'node:crypto';
import { expect, it } from 'vitest';
import {
    evaluateCondition,
    evaluateCustomSignal
} from './condition-evaluator.js';
import {
    CustomSignalOperator,
    PercentConditionOperator,
    type OneOfCondition
} from './remote-config-types.js';

it('evaluates boolean composites and enforces recursion limits', async () => {
    const evaluationResult1 = await evaluateCondition({ true: {} }, {});
    expect(evaluationResult1).toBe(true);
    const evaluationResult2 = await evaluateCondition({ false: {} }, {});
    expect(evaluationResult2).toBe(false);
    const evaluationResult3 = await evaluateCondition({}, {});
    expect(evaluationResult3).toBe(false);
    const evaluationResult4 = await evaluateCondition({ andCondition: {} }, {});
    expect(evaluationResult4).toBe(true);
    const evaluationResult5 = await evaluateCondition({ orCondition: {} }, {});
    expect(evaluationResult5).toBe(false);
    const evaluationResult6 = await evaluateCondition(
        { orCondition: { conditions: [{ false: {} }, { true: {} }] } },
        {}
    );
    expect(evaluationResult6).toBe(true);
    const evaluationResult7 = await evaluateCondition(
        { andCondition: { conditions: [{ true: {} }, { false: {} }] } },
        {}
    );
    expect(evaluationResult7).toBe(false);
    let nested: OneOfCondition = { true: {} };
    for (let index = 0; index < 8; index++) {
        nested = { andCondition: { conditions: [nested] } };
    }
    const evaluationResult8 = await evaluateCondition(nested, {});
    expect(evaluationResult8).toBe(false);
});

it('matches SHA-256 percentage boundaries and seeded assignments', async () => {
    for (const seed of ['', 'cohort']) {
        const randomizationId = 'user-123';
        const hex = createHash('sha256')
            .update(`${seed ? `${seed}.` : ''}${randomizationId}`)
            .digest('hex');
        const bucket = Number(BigInt(`0x${hex}`) % 100000000n);
        const percent = {
            seed,
            percentOperator: PercentConditionOperator.LESS_OR_EQUAL,
            microPercent: bucket
        };
        const evaluationResult9 = await evaluateCondition(
            { percent },
            { randomizationId }
        );
        expect(evaluationResult9).toBe(true);
        const evaluationResult10 = await evaluateCondition(
            { percent: { ...percent, microPercent: bucket - 1 } },
            { randomizationId }
        );
        expect(evaluationResult10).toBe(false);
        const evaluationResult11 = await evaluateCondition(
            {
                percent: {
                    ...percent,
                    percentOperator: PercentConditionOperator.GREATER_THAN,
                    microPercent: bucket - 1
                }
            },
            { randomizationId }
        );
        expect(evaluationResult11).toBe(true);
        const evaluationResult12 = await evaluateCondition(
            {
                percent: {
                    seed,
                    percentOperator: PercentConditionOperator.BETWEEN,
                    microPercentRange: {
                        microPercentLowerBound: bucket - 1,
                        microPercentUpperBound: bucket
                    }
                }
            },
            { randomizationId }
        );
        expect(evaluationResult12).toBe(true);
        const evaluationResult13 = await evaluateCondition({ percent }, {});
        expect(evaluationResult13).toBe(false);
        const evaluationResult14 = await evaluateCondition(
            { percent: { percentOperator: PercentConditionOperator.UNKNOWN } },
            { randomizationId }
        );
        expect(evaluationResult14).toBe(false);
    }
});

it.each([
    ['STRING_CONTAINS', 'Hello world', ['world'], true],
    ['STRING_DOES_NOT_CONTAIN', 'Hello', ['world'], true],
    ['STRING_EXACTLY_MATCHES', ' Hello ', ['Hello'], true],
    ['STRING_EXACTLY_MATCHES', 'Hello', ['hello'], false],
    ['STRING_CONTAINS_REGEX', 'abc123', ['\\d+'], true],
    ['STRING_CONTAINS_REGEX', 'text', ['['], false],
    ['NUMERIC_LESS_THAN', 2, ['3'], true],
    ['NUMERIC_LESS_EQUAL', 2, ['2'], true],
    ['NUMERIC_EQUAL', '2', ['2'], true],
    ['NUMERIC_NOT_EQUAL', 2, ['3'], true],
    ['NUMERIC_GREATER_THAN', 3, ['2'], true],
    ['NUMERIC_GREATER_EQUAL', 3, ['3'], true],
    ['NUMERIC_NOT_EQUAL', 'bad', ['3'], false],
    ['SEMANTIC_VERSION_LESS_THAN', '1.2', ['1.10'], true],
    ['SEMANTIC_VERSION_LESS_EQUAL', '1.2', ['1.2.0'], true],
    ['SEMANTIC_VERSION_EQUAL', '1.2.0', ['1.2'], true],
    ['SEMANTIC_VERSION_NOT_EQUAL', '2', ['1'], true],
    ['SEMANTIC_VERSION_GREATER_THAN', '1.10', ['1.2'], true],
    ['SEMANTIC_VERSION_GREATER_EQUAL', '1.10', ['1.2'], true],
    ['SEMANTIC_VERSION_EQUAL', 'bad', ['1'], false],
    ['SEMANTIC_VERSION_EQUAL', '1.2.3.4.5.6', ['1'], false],
    ['UNKNOWN', 'a', ['a'], false]
] as const)(
    'evaluates %s with %s',
    async (operator, actual, targets, expected) => {
        const condition = {
            customSignalOperator: operator as CustomSignalOperator,
            customSignalKey: 'signal',
            targetCustomSignalValues: [...targets]
        };
        expect(evaluateCustomSignal(condition, { signal: actual })).toBe(
            expected
        );
        const evaluationResult15 = await evaluateCondition(
            { customSignal: condition },
            { signal: actual }
        );
        expect(evaluationResult15).toBe(expected);
        expect(evaluateCustomSignal(condition, {})).toBe(false);
        expect(
            evaluateCustomSignal(
                { ...condition, targetCustomSignalValues: [] },
                { signal: actual }
            )
        ).toBe(false);
    }
);
