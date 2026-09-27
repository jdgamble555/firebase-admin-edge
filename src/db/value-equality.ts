/** @internal Compare Firestore values without depending on object property order. */
export function valueEquals(left: unknown, right: unknown): boolean {
    if (Object.is(left, right)) return true;
    if (
        !left ||
        !right ||
        typeof left !== 'object' ||
        typeof right !== 'object'
    )
        return false;
    if ('isEqual' in left && typeof left.isEqual === 'function')
        return left.isEqual(right);
    if (left instanceof Date)
        return right instanceof Date && left.getTime() === right.getTime();
    if (left instanceof Uint8Array)
        return (
            right instanceof Uint8Array &&
            left.length === right.length &&
            left.every((value, i) => value === right[i])
        );
    if (Array.isArray(left))
        return (
            Array.isArray(right) &&
            left.length === right.length &&
            left.every((value, i) => valueEquals(value, right[i]))
        );
    if (Object.getPrototypeOf(left) !== Object.getPrototypeOf(right))
        return false;
    const keys = Object.keys(left);
    return (
        keys.length === Object.keys(right).length &&
        keys.every(
            (key) =>
                Object.hasOwn(right, key) &&
                valueEquals(
                    (left as Record<string, unknown>)[key],
                    (right as Record<string, unknown>)[key]
                )
        )
    );
}
