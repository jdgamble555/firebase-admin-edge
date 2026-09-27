import type { FieldValue } from './field-value.js';
export type Primitive = string | number | boolean | undefined | null;
export type WithFieldValue<T> =
    | T
    | (T extends Primitive
          ? T
          : T extends object
            ? {
                  [K in keyof T]: T[K] extends Function
                      ? T[K]
                      : WithFieldValue<T[K]> | FieldValue;
              }
            : never);
export type PartialWithFieldValue<T> =
    | Partial<T>
    | (T extends Primitive
          ? T
          : T extends object
            ? {
                  [K in keyof T]?: T[K] extends Function
                      ? T[K]
                      : PartialWithFieldValue<T[K]> | FieldValue;
              }
            : never);
export type UnionToIntersection<U> = (
    U extends unknown ? (value: U) => void : never
) extends (value: infer I) => void
    ? I
    : never;
export type AddPrefixToKeys<Prefix extends string, T> = {
    [K in keyof T & string as `${Prefix}.${K}`]?: string extends K
        ? ChildTypes<T[K]>
        : T[K];
};
export type ChildUpdateFields<K extends string, V> =
    V extends Record<string, unknown>
        ? AddPrefixToKeys<K, UpdateData<V>>
        : never;
export type NestedUpdateFields<T extends object> = UnionToIntersection<
    {
        [K in keyof T & string]: string extends K
            ? never
            : ChildUpdateFields<K, T[K]>;
    }[keyof T & string]
>;
export type UpdateData<T> = T extends Primitive
    ? T
    : T extends object
      ? {
            [K in keyof T]?: string extends K
                ? unknown extends T[K]
                    ? T[K]
                    : PartialWithFieldValue<ChildTypes<T[K]>>
                : UpdateData<T[K]> | FieldValue;
        } & NestedUpdateFields<T>
      : Partial<T>;
export type OrderByDirection = 'asc' | 'desc';
export type DocumentChangeType = 'added' | 'removed' | 'modified';

export type ChildTypes<T> =
    T extends Record<string, unknown>
        ? T | { [K in keyof T & string]: ChildTypes<T[K]> }[keyof T & string]
        : T;
