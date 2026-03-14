import {Primitive, JsonObject} from 'type-fest';

export type ErrorObject = {
	name?: string;
	stack?: string;
	message?: string;
	code?: string;
} & JsonObject;

/**
Serialize an `Error` object into a plain object.

Non-error values are passed through.
Custom properties are preserved.
Circular references are handled.

@example
```
import {serializeError} from 'serialize-error';

const error = new Error('🦄');

console.log(error);
//=> [Error: 🦄]

console.log(serializeError(error));
//=> {name: 'Error', message: '🦄', stack: 'Error: 🦄\n    at Object.<anonymous> …'}
```
*/
export function serializeError<ErrorType>(error: ErrorType): ErrorType extends Primitive
	? ErrorType
	: ErrorObject;

/**
Deserialize a plain object or any value into an `Error` object.

`Error` objects are passed through.
Non-error values are wrapped in a `NonError` error.
Custom properties are preserved.
Non-enumerable properties are kept non-enumerable (name, message, stack).
Enumerable properties are kept enumerable (all properties besides the non-enumerable ones).
Circular references are handled.

@example
```
import {deserializeError} from 'serialize-error';

const error = deserializeError({
	message: 'aaa',
	stack: 'at <anonymous>:1:13'
});

console.log(error);
// Error: aaa
// at <anonymous>:1:13
```
*/
export function deserializeError(errorObject: ErrorObject | unknown): Error;
