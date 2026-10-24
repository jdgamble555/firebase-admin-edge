import type {
    EvaluationContext,
    OneOfCondition,
    CustomSignalCondition
} from './remote-config-types.js';

/** @internal Uses Web Crypto so percentage assignments match Admin SDK SHA-256 buckets. */
export async function evaluateCondition(
    condition: OneOfCondition,
    context: EvaluationContext,
    depth = 0
): Promise<boolean> {
    if (!condition || depth >= 10) {
        return false;
    }
    if (condition.orCondition || condition.andCondition) {
        const isOr = !!condition.orCondition;
        const children =
            (condition.orCondition ?? condition.andCondition)?.conditions ?? [];
        for (const child of children) {
            const result = await evaluateCondition(child, context, depth + 2);
            if (result === isOr) {
                return isOr;
            }
        }
        return !isOr;
    }
    if (condition.true) {
        return true;
    }
    if (condition.false) {
        return false;
    }
    if (condition.percent) {
        if (!context.randomizationId) {
            return false;
        }
        const {
            seed,
            percentOperator,
            microPercent = 0,
            microPercentRange
        } = condition.percent;
        const input = new TextEncoder().encode(
            `${seed ? `${seed}.` : ''}${context.randomizationId}`
        );
        const digest = await crypto.subtle.digest('SHA-256', input);
        const hex = Array.from(new Uint8Array(digest), (byte) =>
            byte.toString(16).padStart(2, '0')
        ).join('');
        const bucket = Number(BigInt(`0x${hex}`) % 100000000n);
        switch (percentOperator) {
            case 'LESS_OR_EQUAL':
                return bucket <= microPercent;
            case 'GREATER_THAN':
                return bucket > microPercent;
            case 'BETWEEN':
                return (
                    bucket > (microPercentRange?.microPercentLowerBound ?? 0) &&
                    bucket <= (microPercentRange?.microPercentUpperBound ?? 0)
                );
            default:
                return false;
        }
    }
    if (condition.customSignal) {
        return evaluateCustomSignal(condition.customSignal, context);
    }
    return false;
}

/** @internal Unknown or malformed conditions never enable a feature. */
export function evaluateCustomSignal(
    condition: CustomSignalCondition,
    context: EvaluationContext
): boolean {
    const {
        customSignalOperator: operator,
        customSignalKey: key,
        targetCustomSignalValues: targets
    } = condition;
    if (
        !operator ||
        !key ||
        !targets?.length ||
        context[key] === undefined ||
        context[key] === null
    ) {
        return false;
    }
    const actual = String(context[key]);
    switch (operator) {
        case 'STRING_CONTAINS':
            return targets.some((target) => actual.includes(target));
        case 'STRING_DOES_NOT_CONTAIN':
            return !targets.some((target) => actual.includes(target));
        case 'STRING_EXACTLY_MATCHES':
            return targets.some((target) => actual.trim() === target.trim());
        case 'STRING_CONTAINS_REGEX':
            try {
                return targets.some((target) =>
                    new RegExp(target).test(actual)
                );
            } catch {
                return false;
            }
    }
    let comparison: number;
    if (operator.startsWith('NUMERIC_')) {
        const left = Number(actual);
        const right = Number(targets[0]);
        if (Number.isNaN(left) || Number.isNaN(right)) {
            return false;
        }
        comparison = left < right ? -1 : left > right ? 1 : 0;
    } else if (operator.startsWith('SEMANTIC_VERSION_')) {
        const left = actual.split('.').map(Number);
        const right = targets[0]!.split('.').map(Number);
        if (
            left.length > 5 ||
            right.length > 5 ||
            [...left, ...right].some(Number.isNaN)
        ) {
            return false;
        }
        comparison = 0;
        for (let index = 0; index < 5; index++) {
            const difference = (left[index] ?? 0) - (right[index] ?? 0);
            if (difference !== 0) {
                comparison = difference < 0 ? -1 : 1;
                break;
            }
        }
    } else {
        return false;
    }
    const suffix = operator.replace(/^(NUMERIC_|SEMANTIC_VERSION_)/, '');
    switch (suffix) {
        case 'LESS_THAN':
            return comparison < 0;
        case 'LESS_EQUAL':
            return comparison <= 0;
        case 'EQUAL':
            return comparison === 0;
        case 'NOT_EQUAL':
            return comparison !== 0;
        case 'GREATER_THAN':
            return comparison > 0;
        case 'GREATER_EQUAL':
            return comparison >= 0;
        default:
            return false;
    }
}
