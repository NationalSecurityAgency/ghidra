# serialize-error [![Build Status](https://travis-ci.org/sindresorhus/serialize-error.svg?branch=master)](https://travis-ci.org/sindresorhus/serialize-error)

> Serialize/deserialize an error into a plain object

Useful if you for example need to `JSON.stringify()` or `process.send()` the error.

## Install

```
$ npm install serialize-error
```

## Usage

```js
const {serializeError, deserializeError} = require('serialize-error');

const error = new Error('🦄');

console.log(error);
//=> [Error: 🦄]

const serialized = serializeError(error)

console.log(serialized);
//=> {name: 'Error', message: '🦄', stack: 'Error: 🦄\n    at Object.<anonymous> …'}

const deserialized = deserializeError(serialized);
//=> [Error: 🦄]
```

## API

### serializeError(value)

Type: `Error | unknown`

Serialize an `Error` object into a plain object.

Non-error values are passed through.
Custom properties are preserved.
Non-enumerable properties are kept non-enumerable (name, message, stack).
Enumerable properties are kept enumerable (all properties besides the non-enumerable ones).
Circular references are handled.

### deserializeError(value)

Type: `{[key: string]: unknown} | unknown`

Deserialize a plain object or any value into an `Error` object.

`Error` objects are passed through.
Non-error values are wrapped in a `NonError` error.
Custom properties are preserved.
Circular references are handled.
