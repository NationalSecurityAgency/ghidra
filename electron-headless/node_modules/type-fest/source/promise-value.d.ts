/**
Returns the type that is wrapped inside a `Promise` type.
If the type is not a `Promise`, the type itself is returned.

@example
```
import {PromiseValue} from 'type-fest';

type AsyncData = Promise<string>;
let asyncData: PromiseValue<AsyncData> = Promise.resolve('ABC');

type Data = PromiseValue<AsyncData>;
let data: Data = await asyncData;

// Here's an example that shows how this type reacts to non-Promise types.
type SyncData = PromiseValue<string>;
let syncData: SyncData = getSyncData();
```
*/
export type PromiseValue<PromiseType, Otherwise = PromiseType> = PromiseType extends Promise<infer Value> ? Value : Otherwise;
